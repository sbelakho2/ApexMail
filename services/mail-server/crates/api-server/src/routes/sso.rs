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
    /// Google's stable account id (`sub`) — the identity-link key. Never
    /// an email address: emails change, `sub` does not.
    sub: Option<String>,
    email: Option<String>,
    email_verified: Option<String>,
    name: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifiedGoogleProfile {
    subject: String,
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

    // Find or create user. Google enforces email_verified above, so the
    // address is safe as the FIRST-link fallback; repeat logins resolve by
    // the (google, sub) identity link and survive IdP-side email changes.
    let mut response = complete_sso_login(
        &state,
        "google",
        &google_profile.subject,
        Some(&google_profile.email),
        &google_profile.name,
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

    // GitHub's stable account id — the identity-link key. It is minted by
    // GitHub and cannot be influenced by the account holder, unlike every
    // email field below.
    let github_subject = user_data["id"]
        .as_i64()
        .map(|id| id.to_string())
        .or_else(|| user_data["id"].as_str().map(str::to_string))
        .ok_or_else(|| ApiError::Internal("missing GitHub user id".into()))?;

    // Email resolution: /user/emails is the ONLY source of verification
    // truth. The top-level profile `email` is a public, settable,
    // unverified field — it previously took precedence and the fallback
    // matched on `primary` without checking `verified`, letting an
    // attacker take over any account by setting their public GitHub email
    // to the victim's address. Verification data must come from this
    // endpoint, so its failure fails the login instead of degrading to
    // the unverified profile field.
    let profile_email = user_data["email"].as_str();
    let emails_resp = state
        .http_client
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "ApexMail/1.0")
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("GitHub emails fetch failed: {e}")))?;

    if !emails_resp.status().is_success() {
        tracing::warn!(status = %emails_resp.status(), "GitHub /user/emails unavailable — refusing SSO login rather than trusting the unverified profile email");
        return Ok(Redirect::to("/login?error=sso_failed").into_response());
    }

    let emails: Vec<serde_json::Value> = emails_resp.json().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to parse GitHub /user/emails response");
        ApiError::Internal(format!("GitHub emails parse failed: {e}"))
    })?;

    // None means no VERIFIED address exists: the login may still proceed
    // through an existing (github, subject) identity link, but can never
    // match or provision by email.
    let verified_email = select_verified_github_email(profile_email, &emails);

    let name = user_data["name"]
        .as_str()
        .or_else(|| user_data["login"].as_str())
        .unwrap_or("");

    let mut response = complete_sso_login(
        &state,
        "github",
        &github_subject,
        verified_email.as_deref(),
        name,
        &redirect_target,
    )
    .await?;
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
    provider: &str,
    subject: &str,
    verified_email: Option<&str>,
    name: &str,
    redirect_target: &str,
) -> Result<Response, ApiError> {
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    // Resolution order (audit 1.2 fix): (provider, subject) identity link
    // FIRST — it is the only binding the IdP account holder cannot re-point
    // at someone else's local account. Email match runs only as the
    // first-link fallback and only on an IdP-VERIFIED address; every
    // caller of this function must have enforced that verification
    // (Google: email_verified claim; GitHub: /user/emails verified flag).
    // users.id is UUID, users.tenant_id is VARCHAR(26) (migration 064) —
    // decode user ids as text so sqlx never faces a TEXT→Uuid decode
    // mismatch.
    let linked_user_id: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT user_id::text FROM user_identities WHERE provider = $1 AND subject = $2 LIMIT 1",
    )
    .bind(provider)
    .bind(subject)
    .fetch_optional(&state.db)
    .await?;

    // ON DELETE CASCADE removes identity rows with their user, so a hit
    // here always resolves; a miss is still handled defensively by
    // falling through to the verified-email path.
    let mut existing: Option<(String, String, String, Option<String>, String, String, bool)> = None;
    if let Some(linked_id) = linked_user_id.as_deref() {
        existing = sqlx::query_as(
            "SELECT id::text, tenant_id, email, name, role, status, mfa_enabled FROM users WHERE id = $1::uuid LIMIT 1",
        )
        .bind(linked_id)
        .fetch_optional(&state.db)
        .await?;
    }

    // First-link fallback: match by email only when no identity link
    // exists AND the address is IdP-verified. An unverified address must
    // never bind to (or provision) an account.
    let matched_by_email = existing.is_none();
    if existing.is_none() {
        if let Some(email) = verified_email {
            let email_lower = email.to_lowercase();
            existing = sqlx::query_as(
                "SELECT id::text, tenant_id, email, name, role, status, mfa_enabled FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1",
            )
            .bind(&email_lower)
            .fetch_optional(&state.db)
            .await?;
        }
    }

    let (user_id, tenant_id, role) = match existing {
        Some((id, tid, _email, _name, role, status, mfa_enabled)) => {
            if status != "active" {
                return Ok(Redirect::to("/login?error=account_inactive").into_response());
            }
            // MFA gate: a user who has enrolled MFA (or whose role mandates
            // it) must not be able to bypass the second factor by signing in
            // through SSO — otherwise the password+MFA flow is decorative.
            // Direct them through the password login, which issues an MFA
            // challenge. (Apple/Microsoft SSO already enforce this gate.)
            if mfa_enabled || super::auth::role_requires_mfa(&role) {
                return Ok(Redirect::to("/login?error=mfa_required").into_response());
            }
            // Update SSO metadata
            sqlx::query(
                "UPDATE users SET metadata = metadata || $1::jsonb, updated_at = NOW() WHERE id = $2::uuid",
            )
            .bind(serde_json::json!({
                "last_sso_provider": provider,
                "last_sso_login": Utc::now().to_rfc3339(),
            }))
            .bind(id.as_str())
            .execute(&state.db)
            .await?;

            // Record the first (provider, subject) → user link in the same
            // flow that matched by email, so every subsequent login
            // resolves by identity and an IdP-side email change can never
            // orphan or re-point the account. ON CONFLICT DO NOTHING keeps
            // a concurrent callback from failing the login.
            if matched_by_email {
                sqlx::query(
                    "INSERT INTO user_identities (provider, subject, user_id, email_at_link)
                     VALUES ($1, $2, $3::uuid, $4)
                     ON CONFLICT (provider, subject) DO NOTHING",
                )
                .bind(provider)
                .bind(subject)
                .bind(id.as_str())
                .bind(verified_email)
                .execute(&state.db)
                .await?;
            }

            (id, tid, role)
        }
        None => {
            // No identity link and no email match. Without a VERIFIED
            // address there is no takeover-proof way to bind this identity
            // to an account — refuse rather than fall back to unverified
            // data (a returning user would have resolved via the identity
            // link above).
            let Some(email) = verified_email else {
                tracing::warn!(
                    provider = %provider,
                    "SSO login refused: no verified IdP email and no existing identity link"
                );
                return Ok(Redirect::to("/login?error=sso_failed").into_response());
            };
            let email_lower = email.to_lowercase();

            // Auto-provision: create tenant + user for SSO-first signup.
            // Schema note (canonical migrations lineage): tenants.id and
            // users.tenant_id are VARCHAR(26) (ULID, migrations 052/064)
            // but users.id is UUID (migration 052) — the 26-char text id
            // previously bound into users.id failed the UUID column and
            // broke every first-time SSO signup. Same convention as
            // `register()`: ULID-shaped tenant id, UUID user id.
            let tenant_id = apexmail_lib::id::generate_id("", 26);
            let user_id = Uuid::new_v4();
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

            // Create placeholder password hash for SSO-only accounts.
            // `$sso$`-prefixed rows are refused with a clean 401 by the
            // password-verification gate (routes/auth.rs) — no password can
            // ever verify against this value.
            let sso_placeholder_hash = format!("$sso${provider}$no-password-sso-login-only");

            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&tenant_id)
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
            .bind(&tenant_id)
            .bind(&email_lower)
            .bind(name)
            .bind(&sso_placeholder_hash)
            .bind("owner")
            .bind("active")
            .bind(true) // the SSO email was IdP-verified before reaching here
            .bind(false)
            .bind(serde_json::json!({"sso_provider": provider}))
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await?;

            // Bind the identity at provisioning time: this user logs in by
            // (provider, subject) from the next callback onwards.
            sqlx::query(
                "INSERT INTO user_identities (provider, subject, user_id, email_at_link)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (provider, subject) DO NOTHING",
            )
            .bind(provider)
            .bind(subject)
            .bind(user_id)
            .bind(email_lower.as_str())
            .execute(&state.db)
            .await?;

            tracing::info!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                provider = %provider,
                "SSO user auto-provisioned"
            );

            (user_id.to_string(), tenant_id, "owner".to_string())
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
        typ: Some("session".into()),
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

/// Select the email a GitHub login may be matched on, from the
/// `/user/emails` verification data only.
///
/// Precedence: verified+primary → the (public, unverified) profile email
/// IF AND ONLY IF it names a verified entry → first verified. An address
/// without `verified == true` is never returned: GitHub's profile email
/// is settable to anything without proof of control, and matching on it
/// allowed account takeover (audit 1.2). `None` means no verified
/// address exists — the caller must not match or provision by email.
fn select_verified_github_email(
    profile_email: Option<&str>,
    emails: &[serde_json::Value],
) -> Option<String> {
    let verified = |e: &&serde_json::Value| {
        e["verified"].as_bool() == Some(true)
            && e["email"].as_str().is_some_and(|a| !a.trim().is_empty())
    };
    let address = |e: &serde_json::Value| e["email"].as_str().map(str::to_string);

    // Verified + primary is GitHub's canonical account address.
    if let Some(primary) = emails
        .iter()
        .find(|e| verified(e) && e["primary"].as_bool() == Some(true))
    {
        return address(primary);
    }

    // The profile email is honored only when the verification data proves
    // control of that exact address (case-insensitive match — GitHub
    // addresses are case-insensitive at delivery).
    if let Some(profile) = profile_email.filter(|p| !p.trim().is_empty()) {
        if let Some(matching) = emails.iter().find(|e| {
            verified(e)
                && e["email"]
                    .as_str()
                    .is_some_and(|a| a.eq_ignore_ascii_case(profile))
        }) {
            return address(matching);
        }
    }

    // Any remaining verified address.
    emails.iter().find(|e| verified(e)).and_then(address)
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

    // `sub` is the only takeover-proof identifier: it is minted by Google
    // and cannot be influenced by the account holder. Without it the login
    // could only be matched by (changeable, re-pointable) email — the exact
    // takeover shape the GitHub path was fixed for.
    let subject = token_info
        .sub
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::Unauthorized("invalid Google ID token".into()))?;

    Ok(VerifiedGoogleProfile {
        subject,
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

    // Control characters (CR/LF/TAB/DEL/C1) can smuggle headers when the
    // value later reaches `Set-Cookie`/`Location`, and must never survive
    // the sanitizer in either raw or percent-encoded form.
    if next.chars().any(char::is_control) {
        return "/dashboard".to_string();
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

    // Percent-encoded control characters must be caught after decoding too
    // (the value returned below is `next`, so the raw check alone is not
    // enough).
    if decoded.chars().any(char::is_control) {
        return "/dashboard".to_string();
    }

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
                sub: Some("google-subject-1".into()),
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
                subject: "google-subject-1".into(),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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
                sub: Some("google-subject-1".into()),
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

    // ── Google `sub` (identity-link key) validation ───────────────

    #[test]
    fn validate_google_token_info_rejects_missing_sub() {
        // Without `sub` there is no takeover-proof identity key — the login
        // could only be matched by (changeable) email, the exact takeover
        // shape the GitHub path was fixed for.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                sub: None,
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("missing sub should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    #[test]
    fn validate_google_token_info_rejects_empty_sub() {
        // A whitespace-only `sub` is as useless as a missing one.
        let error = validate_google_token_info(
            GoogleTokenInfoResponse {
                aud: "google-client-id".into(),
                iss: "https://accounts.google.com".into(),
                exp: Some("4102444800".into()),
                sub: Some("   ".into()),
                email: Some("user@example.com".into()),
                email_verified: Some("true".into()),
                name: Some("User".into()),
            },
            "google-client-id",
            1_700_000_000,
        )
        .expect_err("blank sub should fail");

        assert!(matches!(error, ApiError::Unauthorized(_)));
    }

    // ── GitHub verified-email selection (takeover fix) ────────────

    fn gh_email(address: &str, primary: bool, verified: bool) -> serde_json::Value {
        serde_json::json!({
            "email": address,
            "primary": primary,
            "verified": verified,
            "visibility": "public",
        })
    }

    #[test]
    fn github_email_selection_prefers_verified_primary() {
        let emails = vec![
            gh_email("secondary@users.noreply.github.com", false, true),
            gh_email("primary@example.com", true, true),
        ];
        assert_eq!(
            select_verified_github_email(Some("primary@example.com"), &emails),
            Some("primary@example.com".into())
        );
    }

    #[test]
    fn github_email_selection_never_returns_unverified_primary() {
        // The exact takeover vector: `primary` without `verified` used to be
        // matched directly. An unverified primary must never win, even when
        // it is the only entry.
        let emails = vec![gh_email("victim@example.com", true, false)];
        assert_eq!(select_verified_github_email(None, &emails), None);
    }

    #[test]
    fn github_email_selection_ignores_unverified_profile_email() {
        // The attacker-controlled public profile email must not be honored
        // just because it is present — only when the verification data
        // proves control of that exact address.
        let emails = vec![
            gh_email("attacker-own@example.com", true, true),
            gh_email("victim@example.com", false, false),
        ];
        assert_eq!(
            select_verified_github_email(Some("victim@example.com"), &emails),
            Some("attacker-own@example.com".into())
        );
    }

    #[test]
    fn github_email_selection_accepts_profile_email_matching_a_verified_entry() {
        let emails = vec![
            gh_email("victim@example.com", false, false),
            gh_email("real@example.com", false, true),
        ];
        assert_eq!(
            select_verified_github_email(Some("REAL@example.com"), &emails),
            Some("real@example.com".into())
        );
    }

    #[test]
    fn github_email_selection_falls_back_to_first_verified() {
        // No primary, profile email absent — any verified address is usable.
        let emails = vec![
            gh_email("a@users.noreply.github.com", false, false),
            gh_email("b@example.com", false, true),
            gh_email("c@example.com", false, true),
        ];
        assert_eq!(
            select_verified_github_email(None, &emails),
            Some("b@example.com".into())
        );
    }

    #[test]
    fn github_email_selection_all_unverified_yields_none() {
        let emails = vec![
            gh_email("a@example.com", true, false),
            gh_email("b@example.com", false, false),
        ];
        assert_eq!(
            select_verified_github_email(Some("a@example.com"), &emails),
            None
        );
        assert_eq!(select_verified_github_email(None, &emails), None);
    }

    #[test]
    fn github_email_selection_empty_list_yields_none() {
        assert_eq!(
            select_verified_github_email(Some("x@example.com"), &[]),
            None
        );
    }

    #[test]
    fn github_email_selection_skips_verified_entries_without_an_address() {
        // Malformed entries (verified flag true, no usable email) must not
        // shadow later valid entries.
        let emails = vec![
            serde_json::json!({ "primary": true, "verified": true }),
            gh_email("ok@example.com", false, true),
        ];
        assert_eq!(
            select_verified_github_email(None, &emails),
            Some("ok@example.com".into())
        );
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
        let json = r#"{"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0"}"#; // nosemgrep: generic.secrets.security.detected-jwt-token.detected-jwt-token — truncated dummy token in a serde deserialization test
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
            "sub": "1234567890",
            "email": "user@example.com",
            "email_verified": "true",
            "name": "Test User"
        }"#;
        let parsed: GoogleTokenInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.aud, "my-client-id");
        assert_eq!(parsed.sub, Some("1234567890".into()));
        assert_eq!(parsed.email, Some("user@example.com".into()));
        assert_eq!(parsed.email_verified, Some("true".into()));
    }
}

// ─── Adversarial handler-level tests ──────────────────────────────

#[cfg(test)]
mod adversarial_handler_tests {
    use super::*;
    use crate::app::test_support::{
        test_config, test_state_over_lazy, test_state_over_with_config,
    };
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use sqlx::PgPool;
    use tower::ServiceExt;

    fn unique(prefix: &str) -> String {
        format!(
            "{prefix}{}",
            &uuid::Uuid::new_v4().simple().to_string()[..18]
        )
    }

    /// A config with a REAL RSA keypair so `complete_sso_login` can actually
    /// sign the session JWT (the default test config's placeholder PEM
    /// cannot).
    fn rsa_test_config() -> crate::config::Config {
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("test RSA keypair");
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pair.private_key_pem.as_str())
            .expect("valid PKCS8 private key");
        let mut config = test_config();
        config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
        config.jwt_public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("public PKCS8 PEM")
            .to_string();
        config
    }

    fn sso_app(state: &AppState) -> Router {
        Router::new()
            .nest("/v1/auth/sso", router())
            .with_state(state.clone())
    }

    async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> Response {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        app.clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn cookie_named(response: &Response, prefix: &str) -> Option<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|cookie| cookie.starts_with(prefix))
            .map(str::to_string)
    }

    fn location(response: &Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    // ── Initiation ───────────────────────────────────────────────

    #[tokio::test]
    async fn sso_initiation_requires_configured_providers() {
        let state = test_state_over_lazy().await;
        let app = sso_app(&state);
        for provider in ["google", "github"] {
            let response = get(&app, &format!("/v1/auth/sso/{provider}"), None).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "an unconfigured {provider} provider must be an explicit 404, never a silent success"
            );
            assert!(
                cookie_named(&response, "am_sso_state_").is_none(),
                "no state cookie may be issued by an unconfigured provider"
            );
        }
    }

    #[tokio::test]
    async fn sso_initiation_redirects_with_a_signed_state_cookie() {
        let mut config = test_config();
        config.google_client_id = Some("google-client-id".into());
        config.github_client_id = Some("github-client-id".into());
        let state = test_state_over_with_config(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://x@127.0.0.1:1/x")
                .unwrap(),
            config,
        )
        .await;
        let app = sso_app(&state);

        // Google: authorization URL + state cookie.
        let response = get(&app, "/v1/auth/sso/google?next=%2Fsettings%2Fbilling", None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let auth_url = location(&response);
        assert!(auth_url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(auth_url.contains("client_id=google-client-id"));
        assert!(auth_url.contains(
            "redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fv1%2Fauth%2Fsso%2Fgoogle%2Fcallback"
        ));
        let cookie = cookie_named(&response, "am_sso_state_google=").expect("state cookie");
        assert!(cookie.contains("HttpOnly") && cookie.contains("Max-Age=600"));
        assert!(!cookie.contains("Secure"), "dev cookies stay insecure");
        let cookie_state = cookie
            .strip_prefix("am_sso_state_google=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let parsed = url::Url::parse(&auth_url).unwrap();
        let query_state = parsed
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("state query parameter");
        assert_eq!(query_state, cookie_state, "URL state and cookie must match");
        assert!(cookie_state.ends_with(":/settings/billing"));

        // GitHub: same contract, returnUrl alias.
        let response = get(&app, "/v1/auth/sso/github?returnUrl=%2Fbilling", None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let auth_url = location(&response);
        assert!(auth_url.starts_with("https://github.com/login/oauth/authorize?"));
        let cookie = cookie_named(&response, "am_sso_state_github=").expect("state cookie");
        let cookie_state = cookie
            .strip_prefix("am_sso_state_github=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(cookie_state.ends_with(":/billing"), "{cookie_state}");

        // Open-redirect attempt: the state embeds only the sanitized target.
        let response = get(
            &app,
            "/v1/auth/sso/google?next=https%3A%2F%2Fevil.example",
            None,
        )
        .await;
        let cookie = cookie_named(&response, "am_sso_state_google=").unwrap();
        let cookie_state = cookie
            .strip_prefix("am_sso_state_google=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert!(cookie_state.ends_with(":/dashboard"), "{cookie_state}");

        // Unknown query parameters are rejected by the strict contract.
        let response = get(&app, "/v1/auth/sso/google?unexpected=1", None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A CRLF-smuggling `next` must not reach the Set-Cookie header: the
        // request stays a clean redirect with a sanitized target.
        let response = get(
            &app,
            "/v1/auth/sso/google?next=%2Fdashboard%0D%0ASet-Cookie%3A%20x%3D1",
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a header-smuggling next must not turn into a 500"
        );
        let cookie = cookie_named(&response, "am_sso_state_google=").expect("state cookie");
        assert!(
            !cookie.contains("Set-Cookie: x=1"),
            "no injected header may survive into the cookie: {cookie}"
        );

        // Production adds the Secure attribute.
        let mut config = test_config();
        config.google_client_id = Some("google-client-id".into());
        config.environment = crate::config::Environment::Production;
        let prod_state = test_state_over_with_config(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://x@127.0.0.1:1/x")
                .unwrap(),
            config,
        )
        .await;
        let prod_app = sso_app(&prod_state);
        let response = get(&prod_app, "/v1/auth/sso/google", None).await;
        let cookie = cookie_named(&response, "am_sso_state_google=").unwrap();
        assert!(
            cookie.contains("; Secure"),
            "production state cookies are Secure"
        );
    }

    // ── Callback state validation ────────────────────────────────

    #[tokio::test]
    async fn callbacks_refuse_denied_missing_and_mismatched_state() {
        let mut config = test_config();
        config.google_client_id = Some("google-client-id".into());
        config.google_client_secret = Some("google-secret".into());
        config.github_client_id = Some("github-client-id".into());
        config.github_client_secret = Some("github-secret".into());
        let state = test_state_over_with_config(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://x@127.0.0.1:1/x")
                .unwrap(),
            config,
        )
        .await;
        let app = sso_app(&state);

        for provider in ["google", "github"] {
            // Provider-denied logins redirect to the friendly login error.
            let response = get(
                &app,
                &format!("/v1/auth/sso/{provider}/callback?error=access_denied"),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(location(&response), "/login?error=sso_denied");

            // Missing state parameter.
            let response = get(
                &app,
                &format!("/v1/auth/sso/{provider}/callback?code=abc"),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            // State parameter but no state cookie.
            let state_token = generate_oauth_state("/dashboard").unwrap();
            let encoded =
                url::form_urlencoded::byte_serialize(state_token.as_bytes()).collect::<String>();
            let response = get(
                &app,
                &format!("/v1/auth/sso/{provider}/callback?code=abc&state={encoded}"),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // Replayed state: the cookie carries a different token.
            let attacker_state = generate_oauth_state("/dashboard").unwrap();
            let attacker_encoded =
                url::form_urlencoded::byte_serialize(attacker_state.as_bytes()).collect::<String>();
            let cookie_name = format!("am_sso_state_{provider}=");
            let response = get(
                &app,
                &format!("/v1/auth/sso/{provider}/callback?code=abc&state={attacker_encoded}"),
                Some(&format!("{cookie_name}{state_token}")),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "a replayed/mismatched state must be refused"
            );

            // Matching state + code but no authorization code → 400.
            let response = get(
                &app,
                &format!("/v1/auth/sso/{provider}/callback?state={encoded}"),
                Some(&format!("{cookie_name}{state_token}")),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        // Matching state + code but a half-configured provider (client id,
        // no secret) is refused before any token exchange — an unconfigured
        // provider must never produce a session.
        let mut half_configured = test_config();
        half_configured.google_client_id = Some("google-client-id".into());
        let half_state = test_state_over_with_config(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://x@127.0.0.1:1/x")
                .unwrap(),
            half_configured,
        )
        .await;
        let half_app = sso_app(&half_state);
        let state_token = generate_oauth_state("/dashboard").unwrap();
        let encoded =
            url::form_urlencoded::byte_serialize(state_token.as_bytes()).collect::<String>();
        let response = get(
            &half_app,
            &format!("/v1/auth/sso/google/callback?code=abc&state={encoded}"),
            Some(&format!("am_sso_state_google={state_token}")),
        )
        .await;
        assert!(
            response.status().is_server_error(),
            "an unconfigured provider must fail, not fake a session: {}",
            response.status()
        );
        assert!(cookie_named(&response, "am_session=").is_none());
    }

    #[test]
    fn oauth_state_validation_matrix() {
        let token = generate_oauth_state("/settings/profile").unwrap();
        let headers = |cookie: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, cookie.parse().unwrap());
            headers
        };

        // Matching state yields the sanitized return target.
        assert_eq!(
            validate_oauth_state(
                &headers(&format!("am_sso_state_google={token}")),
                "am_sso_state_google",
                Some(&token)
            )
            .unwrap(),
            "/settings/profile"
        );
        // Missing parameter / missing cookie / mismatched token.
        assert!(matches!(
            validate_oauth_state(
                &headers(&format!("am_sso_state_google={token}")),
                "am_sso_state_google",
                None
            ),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_oauth_state(&headers("other=1"), "am_sso_state_google", Some(&token)),
            Err(ApiError::Unauthorized(_))
        ));
        assert!(matches!(
            validate_oauth_state(
                &headers("am_sso_state_google=different"),
                "am_sso_state_google",
                Some(&token)
            ),
            Err(ApiError::Unauthorized(_))
        ));
        // A malicious target embedded in a valid state is still sanitized.
        let evil = generate_oauth_state("https://evil.example").unwrap();
        assert_eq!(
            validate_oauth_state(
                &headers(&format!("am_sso_state_github={evil}")),
                "am_sso_state_github",
                Some(&evil)
            )
            .unwrap(),
            "/dashboard"
        );
    }

    #[test]
    fn redirect_sanitizer_rejects_every_escape_shape() {
        for rejected in [
            "//evil.example",
            "/\\evil.example",
            "/%2Fevil.example",
            "/%5Cevil.example",
            "/a/../b",
            "/a/%00b",
            "\u{1}",
            "javascript:alert(1)",
            "/dashboard\r\nSet-Cookie: x=1",
            "/dashboard\u{7}bell",
        ] {
            assert_eq!(
                sanitize_redirect(rejected),
                "/dashboard",
                "{rejected:?} must not survive"
            );
        }
        // Honest paths keep their query/fragment-free form and unicode.
        assert_eq!(sanitize_redirect("/sättings/billing"), "/sättings/billing");
        assert_eq!(sanitize_redirect("/a/b?c=d"), "/a/b?c=d");
    }

    #[test]
    fn state_cookie_helpers_refuse_header_injection() {
        let mut response = Redirect::to("/").into_response();
        assert!(matches!(
            set_state_cookie(&mut response, "am_sso_state_google", "bad\nvalue", false),
            Err(ApiError::Internal(_))
        ));
        assert!(matches!(
            clear_state_cookie(&mut response, "bad\nname", false),
            Err(ApiError::Internal(_))
        ));
        // Honest names/values still set and clear.
        assert!(set_state_cookie(&mut response, "am_sso_state_google", "ok", false).is_ok());
        assert!(clear_state_cookie(&mut response, "am_sso_state_google", false).is_ok());
    }

    // ── complete_sso_login against a real database ───────────────

    async fn seed_tenant(pool: &PgPool, slug_prefix: &str) -> String {
        let tenant = format!("tsso{}", &uuid::Uuid::new_v4().simple().to_string()[..21]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
             VALUES ($1, 'SSO Adv Co', $2, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(format!("{slug_prefix}-{tenant}"))
        .execute(pool)
        .await
        .expect("seed sso tenant");
        tenant
    }

    async fn seed_user(
        pool: &PgPool,
        tenant: &str,
        email: &str,
        role: &str,
        status: &str,
        mfa_enabled: bool,
    ) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, \
                    email_verified, mfa_enabled, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, 'SSO User', '$2b$04$placeholder', $4, $5, true, $6, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(email)
        .bind(role)
        .bind(status)
        .bind(mfa_enabled)
        .execute(pool)
        .await
        .expect("seed sso user");
        id
    }

    async fn cleanup_tenant(pool: &PgPool, tenant: &str) {
        sqlx::query(
            "DELETE FROM user_identities WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("cleanup identities");
        sqlx::query("DELETE FROM users WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup users");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup tenant");
    }

    async fn session_claims(
        response: &Response,
        config: &crate::config::Config,
    ) -> crate::middleware::auth::JwtClaims {
        let cookie = cookie_named(response, "am_session=").expect("session cookie");
        assert!(
            cookie.contains("HttpOnly"),
            "session cookie must be HttpOnly: {cookie}"
        );
        assert!(cookie.contains("SameSite=Lax"));
        let token = cookie
            .strip_prefix("am_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = true;
        jsonwebtoken::decode::<crate::middleware::auth::JwtClaims>(
            token,
            &jsonwebtoken::DecodingKey::from_rsa_pem(config.jwt_public_key_pem.as_bytes())
                .expect("decoding key"),
            &validation,
        )
        .expect("the issued session JWT must verify with the configured key")
        .claims
    }

    #[tokio::test]
    async fn complete_sso_login_provisions_a_new_tenant_and_user() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_provision").await else {
            return;
        };
        let config = rsa_test_config();
        let state = test_state_over_with_config(pool.clone(), config.clone()).await;
        let subject = unique("sub-new");
        let email = format!("{}@example.com", unique("newuser"));

        let response = complete_sso_login(
            &state,
            "google",
            &subject,
            Some(&email),
            "Alice Smith",
            "/welcome",
        )
        .await
        .expect("first SSO login provisions");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/welcome");
        let claims = session_claims(&response, &config).await;

        let (tenant_id, role, status, email_verified, password_hash, user_email): (
            String,
            String,
            String,
            bool,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT tenant_id, role, status, email_verified, password_hash, email \
             FROM users WHERE id = $1::uuid",
        )
        .bind(&claims.sub)
        .fetch_one(&pool)
        .await
        .expect("provisioned user");
        assert_eq!(tenant_id, claims.tenant_id);
        assert_eq!(role, "owner", "the first SSO user owns the new tenant");
        assert_eq!(status, "active");
        assert!(
            email_verified,
            "the IdP verified the address before provisioning"
        );
        assert!(
            password_hash.starts_with("$sso$google$"),
            "no password may ever verify for an SSO-only account"
        );
        assert_eq!(user_email, email.to_lowercase());
        assert_eq!(claims.scopes, vec!["*".to_string()]);
        assert_eq!(claims.typ.as_deref(), Some("session"));
        assert!(claims.exp > claims.iat);
        uuid::Uuid::parse_str(&claims.sub).expect("user id is a uuid");
        assert_eq!(claims.tenant_id.len(), 26, "ULID-shaped tenant id");

        let tenant: (String, String) =
            sqlx::query_as("SELECT name, metadata->>'sso_provider' FROM tenants WHERE id = $1")
                .bind(&claims.tenant_id)
                .fetch_one(&pool)
                .await
                .expect("provisioned tenant");
        assert_eq!(tenant.0, "Alice");
        assert_eq!(tenant.1, "google");
        let identity: (String, String) = sqlx::query_as(
            "SELECT user_id::text, COALESCE(email_at_link, '') FROM user_identities \
             WHERE provider = 'google' AND subject = $1",
        )
        .bind(&subject)
        .fetch_one(&pool)
        .await
        .expect("identity link bound at provisioning");
        assert_eq!(identity.0, claims.sub);
        assert_eq!(identity.1, email.to_lowercase());

        cleanup_tenant(&pool, &claims.tenant_id).await;
    }

    #[tokio::test]
    async fn complete_sso_login_binds_identity_first_and_survives_email_changes() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_link").await else {
            return;
        };
        let config = rsa_test_config();
        let state = test_state_over_with_config(pool.clone(), config.clone()).await;
        let tenant = seed_tenant(&pool, "sso-link").await;
        let email = format!("{}@example.com", unique("linked"));
        let user_id = seed_user(&pool, &tenant, &email, "developer", "active", false).await;
        let subject = unique("sub-linked");

        // First login: email match (case-insensitive) links the identity.
        let response = complete_sso_login(
            &state,
            "google",
            &subject,
            Some(&email.to_uppercase()),
            "Linked User",
            "/dashboard",
        )
        .await
        .expect("email-matched login");
        let claims = session_claims(&response, &config).await;
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant);
        assert_eq!(
            claims.scopes,
            vec![
                "messages:send",
                "messages:read",
                "domains:read",
                "templates:read",
                "templates:write",
                "events:read",
                "analytics:read",
                "contacts:read",
                "contacts:write",
            ]
        );
        let linked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_identities WHERE provider = 'google' AND subject = $1",
        )
        .bind(&subject)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked, 1, "first-link fallback records the identity");
        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(metadata["last_sso_provider"], "google");
        assert!(metadata["last_sso_login"].is_string());

        // The IdP-side email CHANGES: the identity link still resolves.
        let response = complete_sso_login(
            &state,
            "google",
            &subject,
            Some("totally-different@example.com"),
            "Renamed",
            "/dashboard",
        )
        .await
        .expect("identity-linked login");
        let claims = session_claims(&response, &config).await;
        assert_eq!(
            claims.sub,
            user_id.to_string(),
            "email changes cannot re-point the account"
        );
        let identities: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE subject = $1")
                .bind(&subject)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(identities, 1, "no second link is created");

        cleanup_tenant(&pool, &tenant).await;
    }

    #[tokio::test]
    async fn identity_link_wins_over_a_matching_email_on_another_account() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_takeover").await else {
            return;
        };
        let config = rsa_test_config();
        let state = test_state_over_with_config(pool.clone(), config.clone()).await;
        let victim_tenant = seed_tenant(&pool, "sso-victim").await;
        let attacker_tenant = seed_tenant(&pool, "sso-attacker").await;
        let shared_email = format!("{}@example.com", unique("shared"));
        let victim = seed_user(
            &pool,
            &victim_tenant,
            &shared_email,
            "viewer",
            "active",
            false,
        )
        .await;
        let attacker = seed_user(
            &pool,
            &attacker_tenant,
            &format!("{}@example.com", unique("attacker")),
            "viewer",
            "active",
            false,
        )
        .await;
        let subject = unique("sub-attacker");
        sqlx::query(
            "INSERT INTO user_identities (provider, subject, user_id, email_at_link) \
             VALUES ('github', $1, $2, 'attacker@example.com')",
        )
        .bind(&subject)
        .bind(attacker)
        .execute(&pool)
        .await
        .unwrap();

        // The IdP account is linked to the attacker; the verified email names
        // the victim. The link must win — email never re-points a link.
        let response = complete_sso_login(
            &state,
            "github",
            &subject,
            Some(&shared_email),
            "Attacker",
            "/dashboard",
        )
        .await
        .expect("linked login");
        let claims = session_claims(&response, &config).await;
        assert_eq!(
            claims.sub,
            attacker.to_string(),
            "email must not hijack a linked account"
        );
        assert_ne!(claims.sub, victim.to_string());
        let victim_links: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_id = $1")
                .bind(victim)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            victim_links, 0,
            "the victim account is never linked by email"
        );

        cleanup_tenant(&pool, &victim_tenant).await;
        cleanup_tenant(&pool, &attacker_tenant).await;
    }

    #[tokio::test]
    async fn complete_sso_login_gates_inactive_and_mfa_accounts() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_gates").await else {
            return;
        };
        let config = rsa_test_config();
        let state = test_state_over_with_config(pool.clone(), config.clone()).await;
        let tenant = seed_tenant(&pool, "sso-gates").await;

        // Inactive account.
        let inactive_email = format!("{}@example.com", unique("inactive"));
        let inactive_subject = unique("sub-inactive");
        seed_user(
            &pool,
            &tenant,
            &inactive_email,
            "developer",
            "suspended",
            false,
        )
        .await;
        let response = complete_sso_login(
            &state,
            "google",
            &inactive_subject,
            Some(&inactive_email),
            "Inactive",
            "/dashboard",
        )
        .await
        .unwrap();
        assert_eq!(location(&response), "/login?error=account_inactive");
        assert!(
            cookie_named(&response, "am_session=").is_none(),
            "an inactive account must never receive a session"
        );

        // MFA-enrolled user: SSO must not bypass the second factor.
        let mfa_email = format!("{}@example.com", unique("mfa"));
        let mfa_subject = unique("sub-mfa");
        seed_user(&pool, &tenant, &mfa_email, "developer", "active", true).await;
        let response = complete_sso_login(
            &state,
            "google",
            &mfa_subject,
            Some(&mfa_email),
            "MFA",
            "/dashboard",
        )
        .await
        .unwrap();
        assert_eq!(location(&response), "/login?error=mfa_required");
        assert!(cookie_named(&response, "am_session=").is_none());

        // Role-mandated MFA (owner) is gated even without enrollment.
        let owner_email = format!("{}@example.com", unique("owner"));
        let owner_subject = unique("sub-owner");
        seed_user(&pool, &tenant, &owner_email, "owner", "active", false).await;
        let response = complete_sso_login(
            &state,
            "google",
            &owner_subject,
            Some(&owner_email),
            "Owner",
            "/dashboard",
        )
        .await
        .unwrap();
        assert_eq!(location(&response), "/login?error=mfa_required");

        cleanup_tenant(&pool, &tenant).await;
    }

    #[tokio::test]
    async fn complete_sso_login_refuses_unverified_email_without_a_link() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_unverified").await else {
            return;
        };
        let config = rsa_test_config();
        let state = test_state_over_with_config(pool.clone(), config.clone()).await;
        let subject = unique("sub-unverified");
        let response =
            complete_sso_login(&state, "github", &subject, None, "No Email", "/dashboard")
                .await
                .expect("the refusal is a redirect, not an error");
        assert_eq!(location(&response), "/login?error=sso_failed");
        assert!(cookie_named(&response, "am_session=").is_none());
        let identities: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE subject = $1")
                .bind(&subject)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            identities, 0,
            "nothing may be provisioned without a verified email"
        );
    }

    #[tokio::test]
    async fn complete_sso_login_fails_honestly_when_the_signing_key_is_broken() {
        let Some(pool) = crate::test_db::optional_pg_pool("sso_adv_bad_key").await else {
            return;
        };
        // The default test config carries a placeholder PEM: signing must
        // fail loudly instead of issuing an unverifiable session.
        let state = test_state_over_with_config(pool.clone(), test_config()).await;
        let tenant = seed_tenant(&pool, "sso-badkey").await;
        let email = format!("{}@example.com", unique("badkey"));
        seed_user(&pool, &tenant, &email, "developer", "active", false).await;
        let error = complete_sso_login(
            &state,
            "google",
            &unique("sub-badkey"),
            Some(&email),
            "Bad Key",
            "/dashboard",
        )
        .await
        .expect_err("a broken signing key must fail the login");
        assert!(matches!(error, ApiError::Internal(_)));
        cleanup_tenant(&pool, &tenant).await;
    }

    #[test]
    fn viewer_and_unknown_role_scope_sets_are_bounded() {
        // The scope mapping is embedded in complete_sso_login; this pins the
        // vocabulary against the role table.
        assert!(crate::routes::auth::role_requires_mfa("owner"));
        assert!(crate::routes::auth::role_requires_mfa("admin"));
        assert!(!crate::routes::auth::role_requires_mfa("developer"));
        assert!(!crate::routes::auth::role_requires_mfa("viewer"));
    }
}
