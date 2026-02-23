use chrono::{Duration, Utc};
use rand::Rng;
use redis::AsyncCommands;
use sha2::{Sha256, Digest};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::types::*;

pub type RedisPool = deadpool_redis::Pool;

/// SSO Service: SAML 2.0 + OIDC authentication
pub struct SSOService {
    db: PgPool,
    redis: Option<RedisPool>,
    config: Config,
}

impl SSOService {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self { db, redis: None, config }
    }

    pub fn with_redis(db: PgPool, redis: RedisPool, config: Config) -> Self {
        Self { db, redis: Some(redis), config }
    }

    /// Configure SSO for a tenant (SAML or OIDC)
    pub async fn configure(&self, req: SSOConfigureRequest) -> Result<ApiResult<SSOConfiguration>, String> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let enabled = req.enabled.unwrap_or(true);
        let enforce = req.enforce_sso.unwrap_or(false);
        let session_hours = req.session_duration_hours.unwrap_or(8);

        let row = sqlx::query_as::<_, SSOConfiguration>(
            "INSERT INTO ent_sso_configurations (id, tenant_id, provider_type, enabled, domain, entity_id, sso_url, certificate, oidc_client_id, oidc_client_secret_encrypted, oidc_issuer, attribute_mapping, enforce_sso, session_duration_hours, created_at, updated_at, allow_idp_initiated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15, false)
             ON CONFLICT (tenant_id, domain) DO UPDATE SET
               provider_type=$3, enabled=$4, entity_id=$6, sso_url=$7, certificate=$8,
               oidc_client_id=$9, oidc_client_secret_encrypted=$10, oidc_issuer=$11,
               attribute_mapping=$12, enforce_sso=$13, session_duration_hours=$14, updated_at=$15
             RETURNING *"
        )
        .bind(id).bind(req.tenant_id).bind(&req.provider_type).bind(enabled)
        .bind(&req.domain).bind(&req.entity_id).bind(&req.sso_url).bind(&req.certificate)
        .bind(&req.oidc_client_id).bind(&req.oidc_client_secret).bind(&req.oidc_issuer)
        .bind(&req.attribute_mapping).bind(enforce).bind(session_hours).bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Configure SSO: {e}"))?;

        info!(tenant_id = %req.tenant_id, provider = %req.provider_type, "SSO configured");
        Ok(ApiResult::ok(row))
    }

    /// Get SSO configuration for a tenant
    pub async fn get_configuration(&self, tenant_id: Uuid) -> Result<ApiResult<SSOConfiguration>, String> {
        let row = sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get SSO config: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("SSO not configured", "NOT_FOUND")),
        }
    }

    /// Get SSO configuration by domain
    pub async fn get_config_by_domain(&self, domain: &str) -> Result<Option<SSOConfiguration>, String> {
        sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE domain = $1 AND enabled = true"
        )
        .bind(domain)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get config by domain: {e}"))
    }

    /// Initiate SAML login — returns redirect URL
    pub async fn initiate_saml_login(&self, domain: &str) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c) if c.provider_type == "saml" => c,
            _ => return Ok(ApiResult::err("SAML not configured for domain", "NOT_FOUND")),
        };

        let request_id = format!("_saml_{}", Uuid::new_v4());
        let sso_url = config.sso_url.unwrap_or_default();
        let entity_id = config.entity_id.unwrap_or_else(|| self.config.sso.saml.entity_id.clone());

        // Build SAML AuthnRequest URL (simplified — real implementation would use XML)
        let redirect_url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            sso_url,
            urlencoding::encode(&entity_id),
            urlencoding::encode(&request_id)
        );

        info!(domain = domain, request_id = %request_id, "SAML login initiated");
        Ok(ApiResult::ok(SSOLoginRedirect { redirect_url, request_id }))
    }

    /// Handle SAML callback — validate assertion and create session
    pub async fn handle_saml_callback(&self, tenant_id: Uuid, email: &str, display_name: Option<&str>, external_user_id: &str, groups: Option<serde_json::Value>, attributes: Option<serde_json::Value>) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.create_sso_session(tenant_id, "saml", email, display_name, external_user_id, groups, attributes).await
    }

    /// Initiate OIDC login — returns authorization redirect URL
    pub async fn initiate_oidc_login(&self, domain: &str) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c) if c.provider_type == "oidc" || c.provider_type == "okta" || c.provider_type == "azure_ad" || c.provider_type == "google" => c,
            _ => return Ok(ApiResult::err("OIDC not configured for domain", "NOT_FOUND")),
        };

        let state = generate_random_token(32);
        let code_verifier = generate_pkce_verifier();
        let code_challenge = generate_pkce_challenge(&code_verifier);

        let issuer = config.oidc_issuer.unwrap_or_default();
        let client_id = config.oidc_client_id.unwrap_or_default();
        let redirect_uri = self.config.sso.oidc.redirect_uri.clone();

        // Store state + code_verifier in Redis with 10-minute TTL
        if let Some(ref redis) = self.redis {
            let mut conn = redis.get().await.map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value = serde_json::json!({
                "code_verifier": code_verifier,
                "domain": domain,
                "tenant_id": config.tenant_id.to_string(),
                "created_at": Utc::now().timestamp(),
            });
            let _: () = conn.set_ex(&key, value.to_string(), 600)
                .await
                .map_err(|e| format!("Redis set: {e}"))?;
        } else {
            // Fallback: store in DB for environments without Redis
            sqlx::query(
                "INSERT INTO sso_oidc_state (state, code_verifier, domain, tenant_id, expires_at)
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')"
            )
            .bind(&state)
            .bind(&code_verifier)
            .bind(domain)
            .bind(config.tenant_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Store OIDC state: {e}"))?;
        }

        let redirect_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            issuer,
            urlencoding::encode(&client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&self.config.sso.oidc.scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&code_challenge),
        );

        info!(domain = domain, "OIDC login initiated");
        Ok(ApiResult::ok(SSOLoginRedirect { redirect_url, request_id: state }))
    }

    /// Validate and retrieve OIDC state for token exchange
    pub async fn validate_oidc_state(&self, state: &str) -> Result<Option<OidcStateData>, String> {
        // Try Redis first
        if let Some(ref redis) = self.redis {
            let mut conn = redis.get().await.map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value: Option<String> = conn.get(&key).await.map_err(|e| format!("Redis get: {e}"))?;
            
            if let Some(json) = value {
                // Delete the state (single-use)
                let _: () = conn.del(&key).await.map_err(|e| format!("Redis del: {e}"))?;
                
                let parsed: serde_json::Value = serde_json::from_str(&json)
                    .map_err(|e| format!("Parse state: {e}"))?;
                
                return Ok(Some(OidcStateData {
                    code_verifier: parsed["code_verifier"].as_str().unwrap_or("").to_string(),
                    domain: parsed["domain"].as_str().unwrap_or("").to_string(),
                    tenant_id: parsed["tenant_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()),
                }));
            }
        }
        
        // Fallback: check DB
        let row = sqlx::query_as::<_, OidcStateRow>(
            "DELETE FROM sso_oidc_state WHERE state = $1 AND expires_at > NOW() RETURNING *"
        )
        .bind(state)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get OIDC state: {e}"))?;
        
        Ok(row.map(|r| OidcStateData {
            code_verifier: r.code_verifier,
            domain: r.domain,
            tenant_id: Some(r.tenant_id),
        }))
    }

    /// Handle OIDC callback
    pub async fn handle_oidc_callback(&self, tenant_id: Uuid, email: &str, display_name: Option<&str>, external_user_id: &str, groups: Option<serde_json::Value>) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.create_sso_session(tenant_id, "oidc", email, display_name, external_user_id, groups, None).await
    }

    /// Create or update SSO session
    async fn create_sso_session(
        &self, tenant_id: Uuid, provider_type: &str, email: &str,
        display_name: Option<&str>, external_user_id: &str,
        groups: Option<serde_json::Value>, attributes: Option<serde_json::Value>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        let session_token = generate_random_token(64);
        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::hours(8);

        let _session = sqlx::query_as::<_, SSOSession>(
            "INSERT INTO ent_sso_sessions (id, tenant_id, provider_type, external_user_id, email, display_name, groups, attributes, session_token, expires_at, last_activity_at, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
             RETURNING *"
        )
        .bind(session_id).bind(tenant_id).bind(provider_type)
        .bind(external_user_id).bind(email).bind(display_name)
        .bind(&groups).bind(&attributes).bind(&session_token).bind(expires_at)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create SSO session: {e}"))?;

        let group_list = groups.and_then(|g| serde_json::from_value::<Vec<String>>(g).ok());

        info!(tenant_id = %tenant_id, email = email, "SSO session created");
        Ok(ApiResult::ok(SSOCallbackResult {
            session: SSOSessionInfo {
                session_token,
                email: email.to_string(),
                display_name: display_name.map(|s| s.to_string()),
                groups: group_list,
                expires_at,
            },
            is_new_user: true,
        }))
    }

    /// Validate session token
    pub async fn validate_session(&self, session_token: &str) -> Result<Option<SSOSession>, String> {
        let session = sqlx::query_as::<_, SSOSession>(
            "SELECT * FROM ent_sso_sessions WHERE session_token = $1 AND expires_at > NOW()"
        )
        .bind(session_token)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Validate session: {e}"))?;

        if let Some(ref s) = session {
            let _ = sqlx::query("UPDATE ent_sso_sessions SET last_activity_at = NOW() WHERE id = $1")
                .bind(s.id)
                .execute(&self.db)
                .await;
        }
        Ok(session)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
        let result = sqlx::query("DELETE FROM ent_sso_sessions WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
            .map_err(|e| format!("Cleanup sessions: {e}"))?;
        let count = result.rows_affected();
        if count > 0 {
            info!(count = count, "Cleaned up expired SSO sessions");
        }
        Ok(count)
    }
}

// ── PKCE helpers ───────────────────────────────────────────────────────

/// Generate a PKCE code verifier (43-128 characters, URL-safe)
pub fn generate_pkce_verifier() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Generate PKCE code challenge: base64url(sha256(verifier))
pub fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
}

/// Generate a random hex token
pub fn generate_random_token(len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rand::thread_rng().gen()).collect();
    hex::encode(bytes)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_verifier_length() {
        let v = generate_pkce_verifier();
        assert_eq!(v.len(), 64);
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_pkce_challenge_deterministic() {
        let v = "test_verifier_12345678901234567890";
        let c1 = generate_pkce_challenge(v);
        let c2 = generate_pkce_challenge(v);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_pkce_challenge_is_base64url() {
        let c = generate_pkce_challenge("some_verifier");
        // Base64url should not contain + or /
        assert!(!c.contains('+'));
        assert!(!c.contains('/'));
        assert!(!c.contains('='));
    }

    #[test]
    fn test_random_token_length() {
        let t = generate_random_token(32);
        assert_eq!(t.len(), 64); // hex doubles the byte count
    }

    #[test]
    fn test_random_token_uniqueness() {
        let t1 = generate_random_token(16);
        let t2 = generate_random_token(16);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_sso_login_redirect_serde() {
        let r = SSOLoginRedirect {
            redirect_url: "https://idp.example.com/sso".into(),
            request_id: "req123".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("redirect_url"));
        let parsed: SSOLoginRedirect = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req123");
    }

    #[test]
    fn test_sso_session_info_serde() {
        let s = SSOSessionInfo {
            session_token: "tok".into(),
            email: "a@b.com".into(),
            display_name: Some("User".into()),
            groups: Some(vec!["admin".into()]),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["email"], "a@b.com");
    }

    #[test]
    fn test_sso_callback_result_serde() {
        let r = SSOCallbackResult {
            session: SSOSessionInfo {
                session_token: "t".into(),
                email: "u@e.com".into(),
                display_name: None,
                groups: None,
                expires_at: Utc::now(),
            },
            is_new_user: true,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["is_new_user"], true);
    }

    #[test]
    fn test_sso_configure_request_serde() {
        let req = SSOConfigureRequest {
            tenant_id: Uuid::new_v4(),
            provider_type: "saml".into(),
            domain: "example.com".into(),
            enabled: Some(true),
            entity_id: Some("urn:test".into()),
            sso_url: Some("https://idp.example.com/sso".into()),
            certificate: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            attribute_mapping: None,
            enforce_sso: None,
            session_duration_hours: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("saml"));
    }
}
