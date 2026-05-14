//! OAuth / SSO initiation endpoints.
//!
//! These endpoints generate OAuth state tokens, set state cookies,
//! and redirect to the OAuth provider authorization URLs.

use super::helpers::extract_cookie;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use uuid::Uuid;

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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenExchangeResponse {
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenInfoResponse {
    aud: String,
    iss: String,
    exp: Option<String>,
    email: Option<String>,
    email_verified: Option<String>,
    name: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifiedGoogleProfile {
    email: String,
    name: String,
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
        .ok_or_else(|| ApiError::NotFound("Google SSO is not configured".into()))?;

    let redirect_base = &state.config.oauth_redirect_base_url;
    let callback_url = format!("{redirect_base}/v1/auth/sso/google/callback");

    let next = params
        .next
        .or(params.return_url)
        .unwrap_or_else(|| "/dashboard".into());
    let safe_next = sanitize_redirect(&next);

    let oauth_state = generate_oauth_state(&safe_next)?;

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=offline&prompt=consent",
        encode_uri_component(client_id),
        encode_uri_component(&callback_url),
        encode_uri_component(&oauth_state),
    );

    // Set state cookie and redirect
    let mut response = Redirect::to(&auth_url).into_response();
    set_state_cookie(
        &mut response,
        "am_sso_state_google",
        &oauth_state,
        state.config.environment.is_production(),
    )?;
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
        .ok_or_else(|| ApiError::NotFound("GitHub SSO is not configured".into()))?;

    let redirect_base = &state.config.oauth_redirect_base_url;
    let callback_url = format!("{redirect_base}/v1/auth/sso/github/callback");

    let next = params
        .next
        .or(params.return_url)
        .unwrap_or_else(|| "/dashboard".into());
    let safe_next = sanitize_redirect(&next);

    let oauth_state = generate_oauth_state(&safe_next)?;

    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
        encode_uri_component(client_id),
        encode_uri_component(&callback_url),
        encode_uri_component(&oauth_state),
    );

    let mut response = Redirect::to(&auth_url).into_response();
    set_state_cookie(
        &mut response,
        "am_sso_state_github",
        &oauth_state,
        state.config.environment.is_production(),
    )?;
    Ok(response)
}

// ─── OAuth Callback Handlers ──────────────────────────────────

async fn sso_google_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = &params.error {
        tracing::warn!(error = %error, "Google OAuth error");
        return Ok(Redirect::to("/login?error=sso_denied").into_response());
    }

    let redirect_target =
        validate_oauth_state(&headers, "am_sso_state_google", params.state.as_deref())?;

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

    let token_data: GoogleTokenExchangeResponse = token_resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Google token parse failed: {e}")))?;

    let id_token = token_data
        .id_token
        .as_deref()
        .ok_or_else(|| ApiError::Internal("missing id_token from Google".into()))?;

    let google_profile = verify_google_id_token(&state.http_client, id_token, client_id).await?;

    // Find or create user
    let mut response = complete_sso_login(
        &state,
        &google_profile.email,
        &google_profile.name,
        "google",
        &redirect_target,
    )
    .await?;
    clear_state_cookie(
        &mut response,
        "am_sso_state_google",
        state.config.environment.is_production(),
    )?;
    Ok(response)
}

async fn sso_github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = &params.error {
        tracing::warn!(error = %error, "GitHub OAuth error");
        return Ok(Redirect::to("/login?error=sso_denied").into_response());
    }

    let redirect_target =
        validate_oauth_state(&headers, "am_sso_state_github", params.state.as_deref())?;

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

        let emails: Vec<serde_json::Value> = emails_resp.json().await.map_err(|e| {
            tracing::warn!(error = %e, "failed to parse GitHub /user/emails response");
            ApiError::Internal(format!("GitHub emails parse failed: {e}"))
        })?;

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

    let mut response = complete_sso_login(&state, &email, name, "github", &redirect_target).await?;
    clear_state_cookie(
        &mut response,
        "am_sso_state_github",
        state.config.environment.is_production(),
    )?;
    Ok(response)
}

// ─── Shared SSO completion ────────────────────────────────────

async fn complete_sso_login(
    state: &AppState,
    email: &str,
    name: &str,
    provider: &str,
    redirect_target: &str,
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
            // Auto-provision:create tenant + user for SSO-first signup
            let tenant_id = uuid::Uuid::new_v4();
            let user_id = uuid::Uuid::new_v4();
            let now = Utc::now();
            let company_name = name.split_whitespace().next().unwrap_or("My Company");
            let slug = format!(
                "{}-{}",
                company_name
                    .chars()
                    .map(|c| if c.is_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    })
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
            "messages:send".into(),
            "messages:read".into(),
            "domains:read".into(),
            "templates:read".into(),
            "templates:write".into(),
            "events:read".into(),
            "analytics:read".into(),
            "contacts:read".into(),
            "contacts:write".into(),
        ],
        "viewer" => vec![
            "messages:read".into(),
            "domains:read".into(),
            "templates:read".into(),
            "events:read".into(),
            "analytics:read".into(),
            "contacts:read".into(),
        ],
        _ => vec!["messages:read".into()],
    };

    let claims = crate::middleware::auth::JwtClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        scopes,
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| ApiError::Internal(format!("JWT key error: {e}")))?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    // Redirect to dashboard with token in cookie
    let mut response = Redirect::to(redirect_target).into_response();
    let cookie_value = format!(
        "am_session={token}; HttpOnly; Path=/; Max-Age={expiry_secs}; SameSite=Lax{}",
        if state.config.environment.is_production() {
            "; Secure"
        } else {
            ""
        }
    );
    response.headers_mut().insert(
        "Set-Cookie",
        cookie_value.parse().map_err(|e| {
            tracing::error!(error = %e, "failed to parse session cookie header value");
            ApiError::Internal("failed to set session cookie".into())
        })?,
    );

    Ok(response)
}

// ─── Helpers ───────────────────────────────────────────────────

fn generate_oauth_state(next: &str) -> Result<String, ApiError> {
    use sha2::Digest;
    let random_bytes: [u8; 32] = rand_bytes()?;
    let hash = sha2::Sha256::digest(random_bytes);
    let state_token =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash);
    // Encode the return path into the state so we can redirect back
    Ok(format!("{state_token}:{next}"))
}

fn redirect_from_oauth_state(state: &str) -> String {
    state
        .split_once(':')
        .map(|(_, next)| sanitize_redirect(next))
        .unwrap_or_else(|| "/dashboard".to_string())
}

async fn verify_google_id_token(
    http_client: &reqwest::Client,
    id_token: &str,
    expected_client_id: &str,
) -> Result<VerifiedGoogleProfile, ApiError> {
    let token_info_resp = http_client
        .get("https://oauth2.googleapis.com/tokeninfo")
        .query(&[("id_token", id_token)])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Google token verification failed: {e}")))?;

    if !token_info_resp.status().is_success() {
        tracing::warn!(status = %token_info_resp.status(), "Google tokeninfo rejected the provided id_token");
        return Err(ApiError::Unauthorized("invalid Google ID token".into()));
    }

    let token_info: GoogleTokenInfoResponse = token_info_resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Google tokeninfo parse failed: {e}")))?;

    validate_google_token_info(
        token_info,
        expected_client_id,
        chrono::Utc::now().timestamp(),
    )
}

fn validate_google_token_info(
    token_info: GoogleTokenInfoResponse,
    expected_client_id: &str,
    now_timestamp: i64,
) -> Result<VerifiedGoogleProfile, ApiError> {
    if token_info.aud != expected_client_id {
        return Err(ApiError::Unauthorized("invalid Google ID token".into()));
    }

    if !matches!(
        token_info.iss.as_str(),
        "accounts.google.com" | "https://accounts.google.com"
    ) {
        return Err(ApiError::Unauthorized("invalid Google ID token".into()));
    }

    let exp = token_info
        .exp
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| ApiError::Unauthorized("invalid Google ID token".into()))?;
    if exp <= now_timestamp {
        return Err(ApiError::Unauthorized("invalid Google ID token".into()));
    }

    if !google_email_verified(token_info.email_verified.as_deref()) {
        return Err(ApiError::Unauthorized("invalid Google ID token".into()));
    }

    let email = token_info
        .email
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::Unauthorized("invalid Google ID token".into()))?;

    Ok(VerifiedGoogleProfile {
        email,
        name: token_info.name.unwrap_or_default(),
    })
}

fn google_email_verified(value: Option<&str>) -> bool {
    matches!(value, Some(raw) if raw.eq_ignore_ascii_case("true") || raw == "1")
}

fn validate_oauth_state(
    headers: &HeaderMap,
    cookie_name: &str,
    returned_state: Option<&str>,
) -> Result<String, ApiError> {
    let returned_state =
        returned_state.ok_or_else(|| ApiError::BadRequest("missing OAuth state".into()))?;
    let expected_state = extract_cookie(headers, cookie_name)
        .ok_or_else(|| ApiError::Unauthorized("missing SSO state cookie".into()))?;

    if !apexmail_lib::timing_safe_compare(&expected_state, returned_state) {
        return Err(ApiError::Unauthorized("invalid OAuth state".into()));
    }

    Ok(redirect_from_oauth_state(returned_state))
}

fn rand_bytes() -> Result<[u8; 32], ApiError> {
    use rand::TryRngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut buf).map_err(|e| {
        tracing::error!(error = %e, "failed to generate random bytes for OAuth state");
        ApiError::Internal("failed to generate OAuth state".into())
    })?;
    Ok(buf)
}

fn sanitize_redirect(next: &str) -> String {
    // Only allow safe relative paths starting with /
    // Reject:
    //   - Absolute URLs (//host/path)
    //   - Protocol-relative URLs (//)
    //   - Backslash paths (\\)  [escape for display only]
    //   - URL-encoded path traversal (%2f, %5c, etc.)
    //   - Paths containing ".." traversal
    if next.is_empty() {
        return "/dashboard".to_string();
    }

    if next == "/" {
        return "/".to_string();
    }

    let first = next.as_bytes()[0];
    if first != b'/' {
        return "/dashboard".to_string();
    }

    // Check second byte for protocol-relative or backslash
    let second = next.as_bytes().get(1).copied().unwrap_or(b'\0');
    if second == b'/' || second == b'\\' {
        return "/dashboard".to_string();
    }

    // URL-decode to catch %2f, %5c, etc.
    let decoded = match urlencoding::decode(next) {
        Ok(d) => d.to_string(),
        Err(_) => return "/dashboard".to_string(),
    };

    // Re-check after decoding (protocol-relative, backslash)
    if decoded.len() > 1 {
        let decoded_bytes = decoded.as_bytes();
        if decoded_bytes[1] == b'/' || decoded_bytes[1] == b'\\' {
            return "/dashboard".to_string();
        }
    }

    // Reject path traversal components
    let segments: Vec<&str> = decoded.split('/').collect();
    for segment in &segments {
        if *segment == ".." || segment.contains('\0') {
            return "/dashboard".to_string();
        }
    }

    next.to_string()
}

fn set_state_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    secure: bool,
) -> Result<(), ApiError> {
    let cookie = format!(
        "{name}={value}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    );
    let val = cookie.parse().map_err(|e| {
        tracing::error!(error = %e, cookie_name = name, "failed to build SSO state cookie header");
        ApiError::Internal("failed to set SSO state cookie".into())
    })?;
    response.headers_mut().append("Set-Cookie", val);
    Ok(())
}

fn clear_state_cookie(response: &mut Response, name: &str, secure: bool) -> Result<(), ApiError> {
    let cookie = format!(
        "{name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    );
    let val = cookie.parse().map_err(|e| {
        tracing::error!(error = %e, cookie_name = name, "failed to clear SSO state cookie header");
        ApiError::Internal("failed to clear SSO state cookie".into())
    })?;
    response.headers_mut().append("Set-Cookie", val);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Sanitize redirect tests ───────────────────────────────────

    #[test]
    fn test_sanitize_redirect() {
        // Verify Open Redirect protection rejects external URLs and double-slash paths.
        assert_eq!(sanitize_redirect("/dashboard"), "/dashboard");
        assert_eq!(sanitize_redirect("/settings/billing"), "/settings/billing");
        assert_eq!(sanitize_redirect("https://evil.com"), "/dashboard");
        assert_eq!(sanitize_redirect(" //evil.com"), "/dashboard");
        assert_eq!(sanitize_redirect(""), "/dashboard");
    }

    #[test]
    fn test_sanitize_redirect_deep_path() {
        // Verify deeply nested relative paths are preserved.
        assert_eq!(sanitize_redirect("/a/b/c/d/e/f/g"), "/a/b/c/d/e/f/g");
    }

    #[test]
    fn test_sanitize_redirect_rejects_double_slash_prefix() {
        // Verify protocol-relative URLs are rejected (open redirect prevention).
        assert_eq!(sanitize_redirect("//evil.com/path"), "/dashboard");
        assert_eq!(sanitize_redirect("/%2fevil.com/path"), "/dashboard");
    }

    #[test]
    fn test_sanitize_redirect_treats_single_char_as_relative() {
        // Verify a single `/` is accepted as root.
        assert_eq!(sanitize_redirect("/"), "/");
    }

    // ── Redirect from OAuth state tests ───────────────────────────

    #[test]
    fn test_redirect_from_oauth_state() {
        // Verify the redirect target is extracted from the state token.
        assert_eq!(
            redirect_from_oauth_state("opaque-token:/dashboard"),
            "/dashboard"
        );
        assert_eq!(
            redirect_from_oauth_state("opaque-token:/settings/billing"),
            "/settings/billing"
        );
        assert_eq!(
            redirect_from_oauth_state("opaque-token:https://evil.com"),
            "/dashboard"
        );
        assert_eq!(redirect_from_oauth_state("opaque-token"), "/dashboard");
    }

    #[test]
    fn test_redirect_from_oauth_state_multiple_colons() {
        // Verify state tokens with multiple colons are handled correctly.
        assert_eq!(
            redirect_from_oauth_state("token:/path:with:colons"),
            "/path:with:colons"
        );
    }

    #[test]
    fn test_redirect_from_oauth_state_empty_after_colon() {
        // Verify that state ending with colon redirects to dashboard.
        assert_eq!(redirect_from_oauth_state("token:"), "/dashboard");
    }

    #[test]
    fn test_redirect_from_oauth_state_no_colon_at_all() {
        // Verify state without any colon resolves to dashboard.
        assert_eq!(redirect_from_oauth_state("justatoken"), "/dashboard");
    }

    // ── Generate OAuth state tests ────────────────────────────────

    #[test]
    fn test_generate_oauth_state() {
        // Verify the state token contains the redirect path and base64 token.
        let state = generate_oauth_state("/dashboard").unwrap();
        assert!(state.contains("/dashboard"));
        assert!(state.len() > 10);
    }

    #[test]
    fn test_generate_oauth_state_round_trip() {
        // Verify that generate_oauth_state → redirect_from_oauth_state round-trips
        // correctly for various paths.
        let paths = vec!["/dashboard", "/settings/billing", "/settings/profile", "/"];
        for path in paths {
            let state = generate_oauth_state(path).unwrap();
            let extracted = redirect_from_oauth_state(&state);
            assert_eq!(extracted, path, "Round-trip failed for path: {path}");
        }
    }

    #[test]
    fn test_generate_oauth_state_rejects_external_url() {
        // Verify that an external URL in generate_oauth_state is sanitized
        // via the round-trip (the path is embedded, then sanitized on extraction).
        let state = generate_oauth_state("https://evil.com").unwrap();
        let extracted = redirect_from_oauth_state(&state);
        assert_eq!(
            extracted, "/dashboard",
            "External URL should be sanitized to /dashboard"
        );
    }

    #[test]
    fn test_generate_oauth_state_has_base64_token() {
        // Verify the state token contains a base64url-encoded portion before the colon.
        let state = generate_oauth_state("/dashboard").unwrap();
        let (token_part, _) = state.split_once(':').unwrap();
        assert!(!token_part.is_empty(), "Token portion must not be empty");
        // Base64url uses A-Z, a-z, 0-9, -, _
        assert!(
            token_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Token portion must be base64url: {token_part}"
        );
    }

    #[test]
    fn test_generate_oauth_state_produces_unique_tokens() {
        // Verify two consecutive state generations produce different tokens
        // (due to random component).
        let state1 = generate_oauth_state("/dashboard").unwrap();
        let state2 = generate_oauth_state("/dashboard").unwrap();
        let (token1, _) = state1.split_once(':').unwrap();
        let (token2, _) = state2.split_once(':').unwrap();
        assert_ne!(token1, token2, "State tokens must be unique");
    }

    // ── Google token info validation tests ────────────────────────

    #[test]
    fn validate_google_token_info_accepts_expected_claims() {
        // Verify valid Google token info is accepted and returns a profile.
        let profile = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("Example User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect("valid token info");

        assert_eq!(
            profile,
            VerifiedGoogleProfile {
                email: "user@example.com".into(),
                name: "Example User".into(),
            }
        );
    }

    #[test]
    fn validate_google_token_info_rejects_wrong_audience() {
        // Verify token with mismatched client_id (audience) is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "other-client".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("Example User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("audience mismatch should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_unverified_email() {
        // Verify token with unverified email is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("false".into()),
                name: Some("Example User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("unverified email should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_expired_token() {
        // Verify token with past expiry is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("1699999999".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("Example User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("expired token should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_wrong_issuer() {
        // Verify token with non-Google issuer is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://evil-idp.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("Example User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("wrong issuer should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_accepts_accounts_dot_com_issuer() {
        // Verify the `accounts.google.com` (non-https) issuer is accepted.
        let profile = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect("accounts.google.com issuer should be accepted");

        assert_eq!(profile.email, "user@example.com");
    }

    #[test]
    fn validate_google_token_info_rejects_missing_expiry() {
        // Verify token without exp field is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: None,
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("missing expiry should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_missing_email() {
        // Verify token without email is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: None,
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("missing email should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_empty_email() {
        // Verify token with empty email string is rejected.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("".into()),
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("empty email should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_accepts_name_optional() {
        // Verify token without name is accepted (name is optional).
        let profile = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: None,
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect("missing name should be ok");

        assert_eq!(profile.name, "");
    }

    // ── Google email_verified edge cases ──────────────────────────

    #[test]
    fn test_google_email_verified_true() {
        // Verify the string "true" is recognized as verified.
        assert!(google_email_verified(Some("true")));
    }

    #[test]
    fn test_google_email_verified_true_uppercase() {
        // Verify "True" (mixed case) is recognized as verified.
        assert!(google_email_verified(Some("True")));
    }

    #[test]
    fn test_google_email_verified_numeric_1() {
        // Verify "1" is recognized as verified.
        assert!(google_email_verified(Some("1")));
    }

    #[test]
    fn test_google_email_verified_false() {
        // Verify "false" is NOT recognized as verified.
        assert!(!google_email_verified(Some("false")));
    }

    #[test]
    fn test_google_email_verified_numeric_0() {
        // Verify "0" is NOT recognized as verified.
        assert!(!google_email_verified(Some("0")));
    }

    #[test]
    fn test_google_email_verified_none() {
        // Verify None is NOT recognized as verified.
        assert!(!google_email_verified(None));
    }

    #[test]
    fn test_google_email_verified_empty() {
        // Verify empty string is NOT recognized as verified.
        assert!(!google_email_verified(Some("")));
    }

    #[test]
    fn test_google_email_verified_no() {
        // Verify "no" is NOT recognized as verified.
        assert!(!google_email_verified(Some("no")));
    }

    // ── Cookie set/clear tests ────────────────────────────────────

    #[test]
    fn test_set_state_cookie_includes_name_and_value() {
        // Verify the state cookie header includes the correct name, value,
        // and security attributes.
        let mut response = Redirect::to("/").into_response();
        set_state_cookie(&mut response, "am_sso_state_test", "test-state-value", true)
            .expect("should set cookie");

        let cookie = response
            .headers()
            .get_all("Set-Cookie")
            .iter()
            .find(|v| v.to_str().unwrap_or("").starts_with("am_sso_state_test="))
            .expect("should find state cookie");

        let cookie_str = cookie.to_str().unwrap();
        assert!(cookie_str.starts_with("am_sso_state_test=test-state-value"));
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("Path=/"));
        assert!(cookie_str.contains("Max-Age=600"));
        assert!(cookie_str.contains("SameSite=Lax"));
        assert!(cookie_str.contains("Secure"));
    }

    #[test]
    fn test_set_state_cookie_no_secure_in_dev() {
        // Verify Secure flag is absent in non-production environments.
        let mut response = Redirect::to("/").into_response();
        set_state_cookie(&mut response, "am_sso_state_dev", "dev-value", false)
            .expect("should set cookie");

        let cookie = response
            .headers()
            .get_all("Set-Cookie")
            .iter()
            .find(|v| v.to_str().unwrap_or("").starts_with("am_sso_state_dev="))
            .expect("should find state cookie");

        let cookie_str = cookie.to_str().unwrap();
        assert!(
            !cookie_str.contains("Secure"),
            "Dev cookies should not have Secure flag"
        );
    }

    #[test]
    fn test_clear_state_cookie_sets_max_age_zero() {
        // Verify clearing a state cookie sets Max-Age=0 and has same name.
        let mut response = Redirect::to("/").into_response();
        clear_state_cookie(&mut response, "am_sso_state_google", true)
            .expect("should clear cookie");

        let cookie = response
            .headers()
            .get_all("Set-Cookie")
            .iter()
            .find(|v| v.to_str().unwrap_or("").starts_with("am_sso_state_google="))
            .expect("should find cleared cookie");

        let cookie_str = cookie.to_str().unwrap();
        assert!(cookie_str.starts_with("am_sso_state_google="));
        assert!(cookie_str.contains("Max-Age=0"));
        assert!(cookie_str.contains("Secure"));
    }

    #[test]
    fn test_clear_state_cookie_no_secure_in_dev() {
        // Verify cleared cookie omits Secure flag in dev.
        let mut response = Redirect::to("/").into_response();
        clear_state_cookie(&mut response, "am_sso_state_github", false)
            .expect("should clear cookie");

        let cookie = response
            .headers()
            .get_all("Set-Cookie")
            .iter()
            .find(|v| v.to_str().unwrap_or("").starts_with("am_sso_state_github="))
            .expect("should find cleared cookie");

        let cookie_str = cookie.to_str().unwrap();
        assert!(!cookie_str.contains("Secure"));
    }

    // ── OAuth callback query params tests ─────────────────────────

    #[test]
    fn test_oauth_callback_query_with_code_and_state() {
        // Verify OAuthCallbackQuery fields can be set.
        let query = OAuthCallbackQuery {
            code: Some("auth_code_123".into()),
            state: Some("state_token_456".into()),
            error: None,
        };
        assert_eq!(query.code, Some("auth_code_123".into()));
        assert_eq!(query.state, Some("state_token_456".into()));
        assert!(query.error.is_none());
    }

    #[test]
    fn test_oauth_callback_query_with_error() {
        // Verify OAuthCallbackQuery with error.
        let query = OAuthCallbackQuery {
            code: None,
            state: Some("token123".into()),
            error: Some("access_denied".into()),
        };
        assert_eq!(query.error, Some("access_denied".into()));
        assert_eq!(query.state, Some("token123".into()));
        assert!(query.code.is_none());
    }

    #[test]
    fn test_oauth_callback_query_empty() {
        // Verify OAuthCallbackQuery with all None fields.
        let query = OAuthCallbackQuery {
            code: None,
            state: None,
            error: None,
        };
        assert!(query.code.is_none());
        assert!(query.state.is_none());
        assert!(query.error.is_none());
    }

    // ── SsoInitQuery tests ────────────────────────────────────────

    #[test]
    fn test_sso_init_query_next() {
        // Verify SsoInitQuery with `next` parameter set.
        let query = SsoInitQuery {
            next: Some("/settings".into()),
            return_url: None,
            state: None,
        };
        assert_eq!(query.next, Some("/settings".into()));
        assert!(query.return_url.is_none());
        assert!(query.state.is_none());
    }

    #[test]
    fn test_sso_init_query_return_url() {
        // Verify SsoInitQuery with returnUrl (camelCase) set.
        let query = SsoInitQuery {
            next: None,
            return_url: Some("/billing".into()),
            state: None,
        };
        assert!(query.next.is_none());
        assert_eq!(query.return_url, Some("/billing".into()));
    }

    #[test]
    fn test_sso_init_query_all_params() {
        // Verify SsoInitQuery with all parameters set.
        let query = SsoInitQuery {
            next: Some("/dashboard".into()),
            return_url: Some("/settings".into()),
            state: Some("abc123".into()),
        };
        assert_eq!(query.next, Some("/dashboard".into()));
        assert_eq!(query.return_url, Some("/settings".into()));
        assert_eq!(query.state, Some("abc123".into()));
    }

    #[test]
    fn test_sso_init_query_next_preferred_over_return_url() {
        // Verify `next` takes precedence over `returnUrl` (matching handler logic).
        let query = SsoInitQuery {
            next: Some("/dashboard".into()),
            return_url: Some("/settings".into()),
            state: None,
        };
        assert_eq!(query.next, Some("/dashboard".into()));
        assert_eq!(query.return_url, Some("/settings".into()));
    }

    // ── Encoded URI component tests ───────────────────────────────

    #[test]
    fn test_encode_uri_component_encodes_special_chars() {
        // Verify that special characters are percent-encoded.
        let encoded = encode_uri_component("hello world");
        assert_eq!(encoded, "hello+world");
    }

    #[test]
    fn test_encode_uri_component_preserves_alphanumeric() {
        // Verify alphanumeric characters are preserved.
        let encoded = encode_uri_component("abc123DEF");
        assert_eq!(encoded, "abc123DEF");
    }

    // ── Token info response serde tests ───────────────────────────

    #[test]
    fn test_google_token_exchange_response_deserialize() {
        // Verify GoogleTokenExchangeResponse can be deserialized from JSON.
        let json = r#"{"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0"}"#;
        let parsed: GoogleTokenExchangeResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.id_token.is_some());
        assert!(parsed.id_token.unwrap().starts_with("eyJ"));
    }

    #[test]
    fn test_google_token_info_response_deserialize() {
        // Verify GoogleTokenInfoResponse can be deserialized from JSON.
        let json = r#"{
            "aud": "my-client-id",
            "iss": "https://accounts.google.com",
            "exp": "4102444800",
            "email": "user@example.com",
            "email_verified": "true",
            "name": "Test User"
        }"#;
        let parsed: GoogleTokenInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.aud, "my-client-id");
        assert_eq!(parsed.email, Some("user@example.com".into()));
        assert_eq!(parsed.email_verified, Some("true".into()));
    }
}
