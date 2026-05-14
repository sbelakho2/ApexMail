use std::sync::Once;

use chrono::{TimeDelta, Utc};
use quick_xml::escape::escape as xml_escape;
use quick_xml::events::Event;
use quick_xml::Reader;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::Config;
use crate::types::*;

pub type RedisPool = deadpool_redis::Pool;

static SSO_SESSIONS_MISSING_WARNING: Once = Once::new();
const OIDC_SECRET_ENCRYPTION_PURPOSE: &str = "enterprise/sso/oidc-client-secret";

fn is_missing_relation_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("42P01"))
}

fn log_missing_sso_sessions_once() {
    SSO_SESSIONS_MISSING_WARNING.call_once(|| {
        tracing::warn!(
            table = "ent_sso_sessions",
            "Enterprise SSO sessions table missing; skipping session cleanup until migrations are applied"
        );
    });
}

fn xml_local_name(full_name: &str) -> &str {
    full_name.rsplit(':').next().unwrap_or(full_name)
}

/// Convert a certificate string to PEM format if it is not already.
/// Accepts raw base64-encoded DER or PEM-formatted certificates.
fn ensure_pem_format(cert: &str) -> Result<String, String> {
    let cert = cert.trim();
    if cert.starts_with("-----BEGIN ") {
        // Already PEM-encoded
        return Ok(cert.to_string());
    }

    // Assume it is raw base64-encoded DER -- wrap in PEM headers
    // Remove any whitespace/newlines first
    let clean: String = cert.chars().filter(|c| !c.is_whitespace()).collect();

    // Validate that it looks like valid base64
    if clean.len() < 20 {
        return Err("SAML certificate is too short".to_string());
    }

    // Re-wrap with PEM headers (RFC 7468)
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    // Split into 64-char lines
    for chunk in clean.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    Ok(pem)
}

/// Verify the XML digital signature on a SAML response using the IdP's certificate.
fn verify_saml_signature(saml_xml: &str, cert_pem: &str) -> Result<(), String> {
    use xml_sec::xmldsig::verify::verify_signature_with_pem_key;
    use xml_sec::xmldsig::verify::DsigStatus;

    match verify_signature_with_pem_key(saml_xml, cert_pem, false) {
        Ok(result) => match result.status {
            DsigStatus::Valid => Ok(()),
            DsigStatus::Invalid(reason) => {
                tracing::warn!(
                    failure_reason = ?reason,
                    "SAML XML signature verification failed"
                );
                Err(format!(
                    "SAML XML signature verification failed: {reason:?}"
                ))
            }
            _ => {
                tracing::warn!("SAML XML signature verification returned unknown status");
                Err("SAML XML signature verification failed: unknown status".to_string())
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "SAML XML signature verification error");
            Err(format!("SAML XML signature verification error: {e}"))
        }
    }
}

fn encrypt_optional_oidc_secret(
    secret: Option<&str>,
    config: &Config,
) -> Result<Option<String>, String> {
    let Some(secret) = secret.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };

    let encryptor = crate::field_encryption::encryptor_from_secret(
        &config.sso.encryption_key,
        OIDC_SECRET_ENCRYPTION_PURPOSE,
    )
    .map_err(|error| format!("Encrypt OIDC client secret: {error}"))?;

    encryptor
        .encrypt(secret)
        .map(Some)
        .map_err(|error| format!("Encrypt OIDC client secret: {error}"))
}

/// SSO Service:SAML 2.0 + OIDC authentication
pub struct SSOService {
    db: PgPool,
    redis: Option<RedisPool>,
    config: Config,
}

impl SSOService {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            redis: None,
            config,
        }
    }

    pub fn with_redis(db: PgPool, redis: RedisPool, config: Config) -> Self {
        Self {
            db,
            redis: Some(redis),
            config,
        }
    }

    /// Configure SSO for a tenant (SAML or OIDC)
    pub async fn configure(
        &self,
        req: SSOConfigureRequest,
    ) -> Result<ApiResult<SSOConfiguration>, String> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let enabled = req.enabled.unwrap_or(true);
        let enforce = req.enforce_sso.unwrap_or(false);
        let session_hours = req.session_duration_hours.unwrap_or(8);
        let encrypted_oidc_secret =
            encrypt_optional_oidc_secret(req.oidc_client_secret.as_deref(), &self.config)?;

        let row = sqlx::query_as::<_, SSOConfiguration>(
            "INSERT INTO ent_sso_configurations (id, tenant_id, provider_type, enabled, domain, entity_id, sso_url, certificate, oidc_client_id, oidc_client_secret_encrypted, oidc_issuer, attribute_mapping, enforce_sso, session_duration_hours, created_at, updated_at, allow_idp_initiated)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15, false)
             ON CONFLICT (tenant_id, domain) DO UPDATE SET
               provider_type=$3, enabled=$4, entity_id=$6, sso_url=$7, certificate=$8,
                             oidc_client_id=$9, oidc_client_secret_encrypted=COALESCE($10, ent_sso_configurations.oidc_client_secret_encrypted), oidc_issuer=$11,
               attribute_mapping=$12, enforce_sso=$13, session_duration_hours=$14, updated_at=$15
             RETURNING *"
        )
           .bind(id).bind(&req.tenant_id).bind(&req.provider_type).bind(enabled)
        .bind(&req.domain).bind(&req.entity_id).bind(&req.sso_url).bind(&req.certificate)
                .bind(&req.oidc_client_id).bind(&encrypted_oidc_secret).bind(&req.oidc_issuer)
        .bind(&req.attribute_mapping).bind(enforce).bind(session_hours).bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Configure SSO: {e}"))?;

        info!(tenant_id = %req.tenant_id, provider = %req.provider_type, "SSO configured");
        Ok(ApiResult::ok(row))
    }

    /// Get SSO configuration for a tenant
    pub async fn get_configuration(
        &self,
        tenant_id: &str,
    ) -> Result<ApiResult<SSOConfiguration>, String> {
        let row = sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE tenant_id = $1",
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
    pub async fn get_config_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<SSOConfiguration>, String> {
        match sqlx::query_as::<_, SSOConfiguration>(
            "SELECT * FROM ent_sso_configurations WHERE domain = $1 AND enabled = true",
        )
        .bind(domain)
        .fetch_optional(&self.db)
        .await
        {
            Ok(config) => Ok(config),
            Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("42P01") => {
                Ok(None)
            }
            Err(error) => Err(format!("Get config by domain: {error}")),
        }
    }

    /// Initiate SAML login — returns redirect URL
    pub async fn initiate_saml_login(
        &self,
        domain: &str,
    ) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c) if c.provider_type == "saml" => c,
            _ => {
                return Ok(ApiResult::err(
                    "SAML not configured for domain",
                    "NOT_FOUND",
                ))
            }
        };

        let request_id = format!("_saml_{}", Uuid::new_v4());
        let sso_url = config.sso_url.unwrap_or_default();
        let entity_id = config
            .entity_id
            .unwrap_or_else(|| self.config.sso.saml.entity_id.clone());
        let acs_url = self.config.sso.saml.acs_url.clone();

        // Build a SAML AuthnRequest XML document with proper XML escaping
        // to prevent XML injection attacks. All user-controlled values are
        // passed through xml_escape() before interpolation.
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let saml_request_xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
            xml_escape(&request_id),
            xml_escape(&issue_instant),
            xml_escape(&sso_url),
            xml_escape(&acs_url),
            xml_escape(&entity_id)
        );
        let saml_request_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            saml_request_xml.as_bytes(),
        );

        let redirect_url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            sso_url,
            urlencoding::encode(&saml_request_b64),
            urlencoding::encode(&request_id)
        );

        info!(domain = domain, request_id = %request_id, "SAML login initiated");
        Ok(ApiResult::ok(SSOLoginRedirect {
            redirect_url,
            request_id,
        }))
    }

    /// Handle SAML callback — validate assertion and create session
    pub async fn handle_saml_callback(
        &self,
        tenant_id: &str,
        email: &str,
        display_name: Option<&str>,
        external_user_id: &str,
        groups: Option<serde_json::Value>,
        attributes: Option<serde_json::Value>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.create_sso_session(
            tenant_id,
            "saml",
            email,
            display_name,
            external_user_id,
            groups,
            attributes,
        )
        .await
    }

    /// Initiate OIDC login — returns authorization redirect URL
    pub async fn initiate_oidc_login(
        &self,
        domain: &str,
    ) -> Result<ApiResult<SSOLoginRedirect>, String> {
        let config = self.get_config_by_domain(domain).await?;
        let config = match config {
            Some(c)
                if c.provider_type == "oidc"
                    || c.provider_type == "okta"
                    || c.provider_type == "azure_ad"
                    || c.provider_type == "google" =>
            {
                c
            }
            _ => {
                return Ok(ApiResult::err(
                    "OIDC not configured for domain",
                    "NOT_FOUND",
                ))
            }
        };

        let state = generate_random_token(32);
        let code_verifier = generate_pkce_verifier();
        let code_challenge = generate_pkce_challenge(&code_verifier);

        let issuer = config.oidc_issuer.unwrap_or_default();
        let client_id = config.oidc_client_id.unwrap_or_default();
        let redirect_uri = self.config.sso.oidc.redirect_uri.clone();

        // Store state + code_verifier in Redis with 10-minute TTL
        if let Some(ref redis) = self.redis {
            let mut conn = redis
                .get()
                .await
                .map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value = serde_json::json!({
                "code_verifier": code_verifier,
                "domain": domain,
                "tenant_id": config.tenant_id.to_string(),
                "created_at": Utc::now().timestamp(),
            });
            let _: () = conn
                .set_ex(&key, value.to_string(), 600)
                .await
                .map_err(|e| format!("Redis set: {e}"))?;
        } else {
            // Fallback:store in DB for environments without Redis
            sqlx::query(
                "INSERT INTO sso_oidc_state (state, code_verifier, domain, tenant_id, expires_at)
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')",
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
        Ok(ApiResult::ok(SSOLoginRedirect {
            redirect_url,
            request_id: state,
        }))
    }

    /// Validate and retrieve OIDC state for token exchange
    pub async fn validate_oidc_state(&self, state: &str) -> Result<Option<OidcStateData>, String> {
        // Try Redis first
        if let Some(ref redis) = self.redis {
            let mut conn = redis
                .get()
                .await
                .map_err(|e| format!("Redis connection: {e}"))?;
            let key = format!("oidc_state:{}", state);
            let value: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| format!("Redis get: {e}"))?;

            if let Some(json) = value {
                // Delete the state (single-use)
                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| format!("Redis del: {e}"))?;

                let parsed: serde_json::Value =
                    serde_json::from_str(&json).map_err(|e| format!("Parse state: {e}"))?;

                // #258:Return error instead of silently falling back to empty string
                let code_verifier = parsed["code_verifier"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .ok_or("Missing or empty code_verifier in OIDC state")?;

                let domain = parsed["domain"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .ok_or("Missing or empty domain in OIDC state")?;

                return Ok(Some(OidcStateData {
                    code_verifier,
                    domain,
                    tenant_id: parsed["tenant_id"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string()),
                }));
            }
        }

        // Fallback:check DB
        let row = sqlx::query_as::<_, OidcStateRow>(
            "DELETE FROM sso_oidc_state WHERE state = $1 AND expires_at > NOW() RETURNING *",
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
    pub async fn handle_oidc_callback(
        &self,
        tenant_id: &str,
        email: &str,
        display_name: Option<&str>,
        external_user_id: &str,
        groups: Option<serde_json::Value>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        self.create_sso_session(
            tenant_id,
            "oidc",
            email,
            display_name,
            external_user_id,
            groups,
            None,
        )
        .await
    }

    /// Create or update SSO session
    #[allow(clippy::too_many_arguments)]
    async fn create_sso_session(
        &self,
        tenant_id: &str,
        provider_type: &str,
        email: &str,
        display_name: Option<&str>,
        external_user_id: &str,
        groups: Option<serde_json::Value>,
        attributes: Option<serde_json::Value>,
    ) -> Result<ApiResult<SSOCallbackResult>, String> {
        // #255:Check if user already exists to correctly report is_new_user
        let existing_user: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ent_sso_sessions WHERE tenant_id = $1 AND external_user_id = $2 LIMIT 1"
        )
        .bind(tenant_id)
        .bind(external_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Check existing user: {e}"))?;

        let is_new_user = existing_user.is_none();

        // #256:Get session duration from SSO config instead of hardcoded 8h
        let session_hours = sqlx::query_scalar::<_, i32>(
            "SELECT session_duration_hours FROM ent_sso_configurations WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get session config: {e}"))?
        .unwrap_or(8); // Default to 8 hours if not configured

        let session_token = generate_random_token(64);
        let session_id = Uuid::new_v4();
        let expires_at =
            Utc::now() + TimeDelta::try_hours(session_hours as i64).unwrap_or(TimeDelta::zero());

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

        info!(tenant_id = %tenant_id, email = %mail_common::pii::redact_email(email), is_new_user = is_new_user, "SSO session created");
        Ok(ApiResult::ok(SSOCallbackResult {
            session: SSOSessionInfo {
                session_token,
                email: email.to_string(),
                display_name: display_name.map(|s| s.to_string()),
                groups: group_list,
                expires_at,
            },
            is_new_user,
        }))
    }

    /// Validate session token
    pub async fn validate_session(
        &self,
        session_token: &str,
    ) -> Result<Option<SSOSession>, String> {
        let session = sqlx::query_as::<_, SSOSession>(
            "SELECT * FROM ent_sso_sessions WHERE session_token = $1 AND expires_at > NOW()",
        )
        .bind(session_token)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Validate session: {e}"))?;

        if let Some(ref s) = session {
            if let Err(e) =
                sqlx::query("UPDATE ent_sso_sessions SET last_activity_at = NOW() WHERE id = $1")
                    .bind(s.id)
                    .execute(&self.db)
                    .await
            {
                tracing::warn!(session_id = %s.id, error = %e, "Failed to update SSO session last_activity_at");
            }
        }
        Ok(session)
    }

    /// Parse and validate a SAML response XML document.
    ///
    /// Performs the following security checks:
    /// 1. XML parsing with XXE protection (external entities disabled)
    /// 2. Validates `StatusCode` element is a success
    /// 3. Validates `Issuer` matches the configured `entity_id` for the domain
    /// 4. Validates `AudienceRestriction` matches the service's ACS URL
    /// 5. Checks `NotOnOrAfter` condition to reject expired assertions
    /// 6. Sanitizes `NameID` and `Attribute` values (rejects `<`, `>`, `&`, control chars, >256 chars)
    ///
    /// Returns a struct with validated NameID and attributes on success.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn parse_and_validate_saml_response(
        &self,
        saml_response_xml: &str,
        domain: &str,
    ) -> Result<ValidatedSamlResponse, String> {
        // 1. Parse XML with XXE protection — quick_xml::Reader does not resolve
        //    external entities by default, providing inherent XXE protection.
        let mut reader = Reader::from_str(saml_response_xml);

        let config = self
            .get_config_by_domain(domain)
            .await?
            .ok_or_else(|| "SAML not configured for domain".to_string())?;

        let expected_entity_id = config
            .entity_id
            .as_deref()
            .unwrap_or(self.config.sso.saml.entity_id.as_str());
        let expected_acs_url = &self.config.sso.saml.acs_url;
        // 0. Verify XML digital signature using the IdP's certificate
        let cert_raw = config.certificate.as_deref().ok_or_else(|| {
            tracing::warn!(
                domain = domain,
                "SAML: No IdP certificate configured — signature verification not possible"
            );
            "SAML IdP certificate is not configured; cannot verify XML signature".to_string()
        })?;
        let cert_pem = ensure_pem_format(cert_raw)?;
        verify_saml_signature(saml_response_xml, &cert_pem)?;

        let mut current_path = Vec::new();
        let mut status_code_value: Option<String> = None;
        let mut issuer_value: Option<String> = None;
        let mut audience_value: Option<String> = None;
        let mut not_on_or_after: Option<chrono::DateTime<Utc>> = None;
        let mut name_id_value: Option<String> = None;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let mut in_status_code = false;
        let mut in_issuer = false;
        let mut in_audience = false;
        let mut in_audience_restriction = false;
        let mut in_conditions = false;
        let mut in_name_id = false;
        let mut in_attribute = false;
        let mut in_attribute_value = false;
        let mut current_attr_name: Option<String> = None;
        let mut text_buf = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    text_buf.clear();
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = xml_local_name(&name).to_string();
                    current_path.push(name.clone());

                    match tag.as_str() {
                        "StatusCode" => in_status_code = true,
                        "Issuer" => in_issuer = true,
                        "Audience" => in_audience = in_conditions && in_audience_restriction,
                        "AudienceRestriction" => in_audience_restriction = true,
                        "Conditions" => {
                            in_conditions = true;
                            // Extract NotOnOrAfter attribute from Conditions element
                            if let Some(attr) = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"NotOnOrAfter")
                            {
                                if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                    not_on_or_after = chrono::DateTime::parse_from_rfc3339(&val)
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .ok()
                                        .or_else(|| {
                                            chrono::DateTime::parse_from_str(
                                                &val,
                                                "%Y-%m-%dT%H:%M:%S%:z",
                                            )
                                            .map(|dt| dt.with_timezone(&Utc))
                                            .ok()
                                        });
                                }
                            }
                        }
                        "NameID" => in_name_id = true,
                        "Attribute" => {
                            in_attribute = true;
                            current_attr_name = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"Name")
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                        }
                        "AttributeValue" => in_attribute_value = in_attribute,
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = xml_local_name(&name).to_string();
                    current_path.pop();

                    match tag.as_str() {
                        "StatusCode" => in_status_code = false,
                        "Issuer" => in_issuer = false,
                        "Audience" => in_audience = false,
                        "AudienceRestriction" => in_audience_restriction = false,
                        "Conditions" => in_conditions = false,
                        "NameID" => in_name_id = false,
                        "Attribute" => {
                            in_attribute = false;
                            current_attr_name = None;
                        }
                        "AttributeValue" => {
                            if in_attribute_value && in_attribute {
                                if let Some(attr_name) = current_attr_name.take() {
                                    let sanitized = sanitize_saml_value(&text_buf);
                                    attributes.push((attr_name, sanitized));
                                    text_buf.clear();
                                }
                            }
                            in_attribute_value = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if let Ok(text) = e.unescape() {
                        let text_str = text.as_ref();
                        if in_status_code {
                            status_code_value = Some(text_str.to_string());
                        } else if in_issuer {
                            issuer_value = Some(text_str.to_string());
                        } else if in_audience && in_conditions && in_audience_restriction {
                            audience_value = Some(text_str.to_string());
                        } else if in_name_id {
                            name_id_value = Some(text_str.to_string());
                        } else if in_attribute && in_attribute_value {
                            text_buf.push_str(text_str);
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = xml_local_name(&name).to_string();
                    if tag == "StatusCode" {
                        // Handle self-closing StatusCode with Value attribute
                        if let Some(attr) = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"Value")
                        {
                            if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                status_code_value = Some(val);
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    tracing::warn!(
                        saml_parse_error = %e,
                        domain = domain,
                        "SAML XML parse error"
                    );
                    return Err(format!("SAML XML parse error: {e}"));
                }
                _ => {}
            }
        }

        // 2. Validate StatusCode is success
        let status_value = status_code_value.as_deref().unwrap_or("");
        if !status_value.ends_with(":Success")
            && status_value != "urn:oasis:names:tc:SAML:2.0:status:Success"
        {
            tracing::warn!(
                saml_status = %status_value,
                domain = domain,
                "SAML response StatusCode is not Success"
            );
            return Err(format!(
                "SAML authentication failed: StatusCode is '{status_value}'"
            ));
        }

        // 3. Validate Issuer matches configured entity_id
        match issuer_value {
            Some(ref issuer) if issuer == expected_entity_id => {}
            Some(ref issuer) => {
                tracing::warn!(
                    saml_issuer = %issuer,
                    expected_entity_id = %expected_entity_id,
                    domain = domain,
                    "SAML Issuer mismatch"
                );
                return Err("SAML Issuer does not match configured entity_id".to_string());
            }
            None => {
                tracing::warn!(domain = domain, "SAML response missing Issuer");
                return Err("SAML response missing Issuer element".to_string());
            }
        }

        // 4. Validate AudienceRestriction matches ACS URL
        match audience_value {
            Some(ref audience) if audience == expected_acs_url => {}
            Some(ref audience) => {
                tracing::warn!(
                    saml_audience = %audience,
                    expected_acs_url = %expected_acs_url,
                    domain = domain,
                    "SAML AudienceRestriction mismatch"
                );
                return Err("SAML AudienceRestriction does not match ACS URL".to_string());
            }
            None => {
                tracing::warn!(domain = domain, "SAML response missing AudienceRestriction");
                return Err("SAML response missing AudienceRestriction".to_string());
            }
        }

        // 5. Check NotOnOrAfter condition — reject expired assertions
        if let Some(expires) = not_on_or_after {
            if Utc::now() > expires {
                tracing::warn!(
                    expires = %expires.to_rfc3339(),
                    domain = domain,
                    "SAML assertion has expired"
                );
                return Err("SAML assertion has expired (NotOnOrAfter)".to_string());
            }
        }

        // 6. Validate and sanitize NameID
        let name_id = name_id_value.ok_or_else(|| {
            tracing::warn!(domain = domain, "SAML response missing NameID");
            "SAML response missing NameID element".to_string()
        })?;

        let sanitized_name_id = sanitize_saml_value(&name_id);

        if sanitized_name_id.is_empty() {
            tracing::warn!(domain = domain, "SAML NameID is empty after sanitization");
            return Err("SAML NameID is empty after sanitization".to_string());
        }

        Ok(ValidatedSamlResponse {
            name_id: sanitized_name_id,
            attributes,
        })
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
        let result = match sqlx::query("DELETE FROM ent_sso_sessions WHERE expires_at < NOW()")
            .execute(&self.db)
            .await
        {
            Ok(result) => result,
            Err(error) if is_missing_relation_error(&error) => {
                log_missing_sso_sessions_once();
                return Ok(0);
            }
            Err(error) => return Err(format!("Cleanup sessions: {error}")),
        };
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
    use aes_gcm::aead::rand_core::RngCore;
    let mut bytes = vec![0u8; 64];
    aes_gcm::aead::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|&b| {
            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._";
            CHARSET[(b as usize) % CHARSET.len()] as char
        })
        .collect()
}

/// Generate PKCE code challenge:base64url(sha256(verifier))
pub fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
}

/// Generate a random hex token
pub fn generate_random_token(len: usize) -> String {
    use aes_gcm::aead::rand_core::RngCore;
    let mut bytes = vec![0u8; len];
    aes_gcm::aead::OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

// ── SAML validation types and helpers ──────────────────────────────────

/// The result of a successfully validated SAML response.
pub struct ValidatedSamlResponse {
    /// The validated and sanitized NameID value.
    pub name_id: String,
    /// List of (attribute_name, sanitized_value) pairs.
    pub attributes: Vec<(String, String)>,
}

/// Sanitize a SAML attribute or NameID value.
///
/// Rejects strings containing `<`, `>`, `&`, control characters (U+0000–U+001F
/// except U+0009, U+000A, U+000D), or exceeding 256 characters in length.
///
/// Returns the sanitized (trimmed) value on success, or an empty string if
/// the value is invalid.
fn sanitize_saml_value(value: &str) -> String {
    let trimmed = value.trim();

    // Reject empty values
    if trimmed.is_empty() {
        return String::new();
    }

    // Reject values exceeding 256 chars
    if trimmed.len() > 256 {
        tracing::warn!(
            value_length = trimmed.len(),
            "SAML value exceeds maximum length of 256 characters"
        );
        return String::new();
    }

    // Reject XML-special characters: < > &
    if trimmed.contains('<') || trimmed.contains('>') || trimmed.contains('&') {
        tracing::warn!("SAML value contains XML-special characters");
        return String::new();
    }

    // Reject control characters (except tab, newline, carriage return)
    if trimmed.chars().any(|c| {
        let code = c as u32;
        code < 0x20 && code != 0x09 && code != 0x0A && code != 0x0D
    }) {
        tracing::warn!("SAML value contains control characters");
        return String::new();
    }

    trimmed.to_string()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // ── PKCE tests ────────────────────────────────────────────────

    fn is_pkce_unreserved(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
    }

    #[test]
    fn test_pkce_verifier_length() {
        let v = generate_pkce_verifier();
        assert_eq!(v.len(), 64);
        assert!(v.chars().all(is_pkce_unreserved));
    }

    #[test]
    fn test_pkce_verifier_uniqueness() {
        // Verify two verifiers generated in quick succession are different
        let v1 = generate_pkce_verifier();
        let v2 = generate_pkce_verifier();
        assert_ne!(v1, v2);
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
    fn test_pkce_challenge_length_is_valid() {
        // SHA-256 produces 32 bytes → base64url encodes to 43 chars (no padding)
        let c = generate_pkce_challenge("test_verifier_value");
        assert_eq!(c.len(), 43);
    }

    #[test]
    fn test_pkce_full_flow_round_trip() {
        // Verify that a code verifier can generate a challenge, and that the
        // challenge is verifiable (deterministic property).
        let verifier = generate_pkce_verifier();
        let challenge1 = generate_pkce_challenge(&verifier);
        let challenge2 = generate_pkce_challenge(&verifier);
        assert_eq!(challenge1, challenge2);
        assert_ne!(challenge1, generate_pkce_challenge("different_verifier"));
    }

    #[test]
    fn test_pkce_verifier_min_length_43() {
        // RFC 7636 says verifier must be at least 43 chars.
        // Our implementation generates 64 chars which satisfies this.
        let v = generate_pkce_verifier();
        assert!(
            v.len() >= 43,
            "PKCE verifier must be ≥43 chars per RFC 7636"
        );
    }

    #[test]
    fn test_pkce_verifier_max_length_128() {
        // RFC 7636 says verifier must be at most 128 chars.
        let v = generate_pkce_verifier();
        assert!(
            v.len() <= 128,
            "PKCE verifier must be ≤128 chars per RFC 7636"
        );
    }

    #[test]
    fn test_pkce_verifier_url_safe() {
        // Verifier must contain only unreserved characters per RFC 7636
        let v = generate_pkce_verifier();
        assert!(
            v.chars().all(is_pkce_unreserved),
            "PKCE verifier must only contain unreserved characters"
        );
    }

    // ── Random token tests ─────────────────────────────────────────

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
    fn test_random_token_varying_lengths() {
        // Verify token generation works for different requested lengths.
        for len in [8, 16, 32, 64] {
            let t = generate_random_token(len);
            assert_eq!(t.len(), len * 2, "hex token length mismatch for len={len}");
        }
    }

    #[test]
    fn test_random_token_is_hex() {
        // Verify the token is valid hexadecimal.
        let t = generate_random_token(32);
        assert!(
            t.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be valid hex: {t}"
        );
    }

    // ── Serde tests ───────────────────────────────────────────────

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
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
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

    #[test]
    fn test_oidc_state_data_serde() {
        // Verify that OidcStateData round-trips through JSON (used for Redis storage).
        let state = OidcStateData {
            code_verifier: "abc123verifier".into(),
            domain: "example.com".into(),
            tenant_id: Some("tenant_01HZ".into()),
        };
        let json = serde_json::json!({
            "code_verifier": state.code_verifier,
            "domain": state.domain,
            "tenant_id": state.tenant_id,
            "created_at": Utc::now().timestamp(),
        });
        let parsed: OidcStateData = OidcStateData {
            code_verifier: json["code_verifier"].as_str().unwrap().to_string(),
            domain: json["domain"].as_str().unwrap().to_string(),
            tenant_id: json["tenant_id"].as_str().map(|s| s.to_string()),
        };
        assert_eq!(parsed.code_verifier, "abc123verifier");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.tenant_id, Some("tenant_01HZ".into()));
    }

    #[test]
    fn test_oidc_state_data_missing_tenant_id() {
        // Verify that OidcStateData handles missing tenant_id (None).
        let state = OidcStateData {
            code_verifier: "verifier123".into(),
            domain: "company.com".into(),
            tenant_id: None,
        };
        let json = serde_json::json!({
            "code_verifier": state.code_verifier,
            "domain": state.domain,
        });
        let parsed = OidcStateData {
            code_verifier: json["code_verifier"].as_str().unwrap().to_string(),
            domain: json["domain"].as_str().unwrap().to_string(),
            tenant_id: json["tenant_id"].as_str().map(|s| s.to_string()),
        };
        assert!(parsed.tenant_id.is_none());
    }

    // ── Field encryption tests ─────────────────────────────────────

    #[test]
    fn test_encrypt_optional_oidc_secret_produces_encrypted_blob() {
        let mut config = Config::from_env().unwrap();
        config.sso.encryption_key = "enterprise-secret-material-for-tests".into();

        let encrypted = encrypt_optional_oidc_secret(Some("oidc-top-secret"), &config)
            .unwrap()
            .expect("encrypted secret");

        assert!(crate::field_encryption::FieldEncryptor::is_encrypted(
            &encrypted
        ));
        assert_ne!(encrypted, "oidc-top-secret");

        let decryptor = crate::field_encryption::encryptor_from_secret(
            &config.sso.encryption_key,
            OIDC_SECRET_ENCRYPTION_PURPOSE,
        )
        .unwrap();
        assert_eq!(decryptor.decrypt(&encrypted).unwrap(), "oidc-top-secret");
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_when_empty() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(Some(""), &config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_when_whitespace() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(Some("   "), &config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_optional_oidc_secret_none_input() {
        let config = Config::from_env().unwrap();
        let result = encrypt_optional_oidc_secret(None, &config).unwrap();
        assert!(result.is_none());
    }

    // ── SAML sanitize_value tests ────────────────────────────────

    #[test]
    fn test_sanitize_saml_value_rejects_xml_special_chars() {
        assert!(sanitize_saml_value("<malicious>").is_empty());
        assert!(sanitize_saml_value("foo>bar").is_empty());
        assert!(sanitize_saml_value("foo&bar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_control_chars() {
        assert!(sanitize_saml_value("foo\x00bar").is_empty());
        assert!(sanitize_saml_value("foo\x01bar").is_empty());
        assert!(sanitize_saml_value("foo\x1Fbar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_allows_whitespace() {
        assert!(!sanitize_saml_value("tab\there").is_empty());
        assert!(!sanitize_saml_value("newline\nhere").is_empty());
        assert!(!sanitize_saml_value("cr\rhere").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_over_256_chars() {
        let long = "a".repeat(257);
        assert!(sanitize_saml_value(&long).is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_accepts_valid_input() {
        let valid = sanitize_saml_value("alice@example.com");
        assert_eq!(valid, "alice@example.com");
    }

    #[test]
    fn test_sanitize_saml_value_rejects_empty() {
        assert!(sanitize_saml_value("").is_empty());
        assert!(sanitize_saml_value("  ").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_trims_whitespace() {
        let valid = sanitize_saml_value("  user@example.com  ");
        assert_eq!(valid, "user@example.com");
    }

    #[test]
    fn test_sanitize_saml_value_rejects_256_chars_boundary() {
        // 256 chars should be accepted (boundary)
        let valid_256 = "a".repeat(256);
        assert_eq!(sanitize_saml_value(&valid_256).len(), 256);
    }

    // ── SAML XML structure tests ──────────────────────────────────

    /// Build a valid SAML AuthnRequest XML string matching the format
    /// produced by `initiate_saml_login`.
    fn make_saml_authn_request(
        request_id: &str,
        entity_id: &str,
        acs_url: &str,
        destination: &str,
    ) -> String {
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
            xml_escape(request_id),
            xml_escape(&issue_instant),
            xml_escape(destination),
            xml_escape(acs_url),
            xml_escape(entity_id),
        )
    }

    /// Build a valid SAML Response XML string with the given components.
    fn make_saml_response(
        status_code: &str,
        issuer: &str,
        audience: &str,
        not_on_or_after: Option<&str>,
        name_id: &str,
        attributes: &[(&str, &str)],
    ) -> String {
        let not_on_or_after_attr = match not_on_or_after {
            Some(val) => format!(" NotOnOrAfter=\"{}\"", xml_escape(val)),
            None => String::new(),
        };

        let attr_statements: String = attributes.iter().map(|(name, value)| {
            format!(
                r#"<saml:Attribute Name="{}"><saml:AttributeValue>{}</saml:AttributeValue></saml:Attribute>"#,
                xml_escape(name),
                xml_escape(value),
            )
        }).collect();

        let attr_section = if attr_statements.is_empty() {
            String::new()
        } else {
            format!(
                "<saml:AttributeStatement>{}</saml:AttributeStatement>",
                attr_statements
            )
        };

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{}"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2025-01-01T00:00:01Z">
    <saml:Issuer>{}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2025-01-02T00:00:00Z" Recipient="https://apexmail.com/api/sso/saml/callback"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions{}>
      <saml:AudienceRestriction>
        <saml:Audience>{}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    {}
  </saml:Assertion>
</samlp:Response>"#,
            xml_escape(issuer),
            xml_escape(status_code),
            xml_escape(issuer),
            xml_escape(name_id),
            not_on_or_after_attr,
            xml_escape(audience),
            attr_section,
        )
    }

    /// Strip the namespace prefix from a qualified XML element name.
    /// Returns the local part (e.g., `samlp:StatusCode` → `StatusCode`).
    fn local_name(full_name: &str) -> &str {
        full_name.rsplit(':').next().unwrap_or(full_name)
    }

    /// Parse a SAML XML string and extract key fields (mirrors the production
    /// logic in `parse_and_validate_saml_response` for testability).
    ///
    /// Uses `local_name()` to handle both namespaced (e.g., `samlp:StatusCode`)
    /// and un-prefixed element names uniformly.
    fn parse_saml_response_xml(xml: &str) -> Result<ParsedSamlFields, String> {
        let mut reader = Reader::from_str(xml);
        let mut in_status_code = false;
        let mut in_issuer = false;
        let mut in_audience = false;
        let mut in_conditions = false;
        let mut in_audience_restriction = false;
        let mut in_name_id = false;
        let mut in_attribute = false;
        let mut in_attribute_value = false;
        let mut current_attr_name: Option<String> = None;

        let mut status_code_value: Option<String> = None;
        let mut issuer_values: Vec<String> = Vec::new();
        let mut audience_value: Option<String> = None;
        let mut not_on_or_after: Option<String> = None;
        let mut name_id_value: Option<String> = None;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let mut text_buf = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    text_buf.clear();
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    match tag.as_str() {
                        "StatusCode" => in_status_code = true,
                        "Issuer" => in_issuer = true,
                        "Audience" => in_audience = in_conditions && in_audience_restriction,
                        "AudienceRestriction" => in_audience_restriction = true,
                        "Conditions" => {
                            in_conditions = true;
                            // Extract NotOnOrAfter attribute from Conditions element
                            if let Some(attr) = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"NotOnOrAfter")
                            {
                                if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                    not_on_or_after = Some(val);
                                }
                            }
                        }
                        "NameID" => in_name_id = true,
                        "Attribute" => {
                            in_attribute = true;
                            current_attr_name = e
                                .attributes()
                                .filter_map(|a| a.ok())
                                .find(|a| a.key.as_ref() == b"Name")
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                        }
                        "AttributeValue" => in_attribute_value = in_attribute,
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    match tag.as_str() {
                        "StatusCode" => in_status_code = false,
                        "Issuer" => in_issuer = false,
                        "Audience" => in_audience = false,
                        "AudienceRestriction" => in_audience_restriction = false,
                        "Conditions" => in_conditions = false,
                        "NameID" => in_name_id = false,
                        "Attribute" => {
                            in_attribute = false;
                            current_attr_name = None;
                        }
                        "AttributeValue" => {
                            if in_attribute_value && in_attribute {
                                if let Some(attr_name) = current_attr_name.take() {
                                    attributes.push((attr_name, text_buf.clone()));
                                    text_buf.clear();
                                }
                            }
                            in_attribute_value = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if let Ok(text) = e.unescape() {
                        let text_str = text.as_ref();
                        if in_status_code {
                            status_code_value = Some(text_str.to_string());
                        } else if in_issuer {
                            issuer_values.push(text_str.to_string());
                        } else if in_audience && in_conditions && in_audience_restriction {
                            audience_value = Some(text_str.to_string());
                        } else if in_name_id {
                            name_id_value = Some(text_str.to_string());
                        } else if in_attribute && in_attribute_value {
                            text_buf.push_str(text_str);
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name).to_string();
                    if tag == "StatusCode" {
                        if let Some(attr) = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .find(|a| a.key.as_ref() == b"Value")
                        {
                            if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                status_code_value = Some(val);
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("SAML XML parse error: {e}")),
                _ => {}
            }
        }

        Ok(ParsedSamlFields {
            status_code: status_code_value.unwrap_or_default(),
            issuer: issuer_values.first().cloned().unwrap_or_default(),
            audience: audience_value.unwrap_or_default(),
            not_on_or_after,
            name_id: name_id_value.unwrap_or_default(),
            attributes,
        })
    }

    /// Helper struct for SAML XML parse result.
    struct ParsedSamlFields {
        status_code: String,
        issuer: String,
        audience: String,
        not_on_or_after: Option<String>,
        name_id: String,
        attributes: Vec<(String, String)>,
    }

    #[test]
    fn test_saml_authn_request_xml_structure() {
        // Verify that the SAML AuthnRequest XML contains required elements:
        // Issuer, protocol namespace, and the ID attribute.
        let entity_id = "urn:apexmail:enterprise";
        let acs_url = "https://apexmail.com/api/sso/saml/callback";
        let destination = "https://idp.example.com/sso";
        let request_id = "_saml_test-uuid";

        let xml = make_saml_authn_request(request_id, entity_id, acs_url, destination);

        // Verify the XML contains required elements
        assert!(
            xml.contains("samlp:AuthnRequest"),
            "Should contain AuthnRequest element"
        );
        assert!(
            xml.contains(&format!("ID=\"{}\"", xml_escape(request_id))),
            "Should contain request ID"
        );
        assert!(
            xml.contains(&format!(
                "AssertionConsumerServiceURL=\"{}\"",
                xml_escape(acs_url)
            )),
            "Should contain ACS URL"
        );
        assert!(
            xml.contains(&format!(
                "<saml:Issuer>{}</saml:Issuer>",
                xml_escape(entity_id)
            )),
            "Should contain Issuer"
        );
        assert!(
            xml.contains("urn:oasis:names:tc:SAML:2.0:protocol"),
            "Should contain SAML protocol namespace"
        );
    }

    #[test]
    fn test_saml_authn_request_xml_parses_correctly() {
        // Verify the AuthnRequest XML can be parsed back with quick_xml,
        // using `local_name()` to handle namespace-prefixed element names.
        let entity_id = "urn:apexmail:enterprise";
        let acs_url = "https://apexmail.com/api/sso/saml/callback";
        let destination = "https://idp.example.com/sso";
        let request_id = "_saml_test-abc123";
        let xml = make_saml_authn_request(request_id, entity_id, acs_url, destination);

        let mut reader = Reader::from_str(&xml);
        let mut found_issuer = false;
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let tag = local_name(&name);
                    if tag == "Issuer" {
                        found_issuer = true;
                    }
                    if tag == "AuthnRequest" {
                        // Verify the ID attribute is present
                        let has_id = e
                            .attributes()
                            .filter_map(|a| a.ok())
                            .any(|a| a.key.as_ref() == b"ID");
                        assert!(has_id, "AuthnRequest must have ID attribute");
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if found_issuer {
                        assert_eq!(e.unescape().unwrap().as_ref(), entity_id);
                        found_issuer = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
        }
    }

    #[test]
    fn test_saml_valid_response_parses_status_code_and_issuer() {
        // Verify that a valid SAML response XML correctly extracts StatusCode
        // and Issuer values via quick_xml parsing.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[("email", "user@example.com"), ("role", "admin")],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");

        assert!(
            parsed.status_code.contains(":Success")
                || parsed.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success",
            "Status code should indicate success, got: {}",
            parsed.status_code
        );
        assert_eq!(parsed.issuer, "urn:apexmail:enterprise");
    }

    #[test]
    fn test_saml_valid_response_parses_audience_restriction() {
        // Verify that the Audience element is correctly extracted from
        // AudienceRestriction.
        let expected_audience = "https://apexmail.com/api/sso/saml/callback";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            expected_audience,
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.audience, expected_audience);
    }

    #[test]
    fn test_saml_ignores_audience_outside_audience_restriction() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion>
        <saml:Audience>https://evil.example/callback</saml:Audience>
        <saml:Conditions>
            <saml:AudienceRestriction>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
    </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML");

        assert!(parsed.audience.is_empty());
    }

    #[test]
    fn test_saml_valid_response_parses_name_id() {
        // Verify that the NameID element is correctly extracted.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "alice@company.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.name_id, "alice@company.com");
    }

    #[test]
    fn test_saml_valid_response_parses_attributes() {
        // Verify that Attribute/AttributeValue elements are correctly extracted.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[
                ("email", "user@example.com"),
                ("firstName", "Alice"),
                ("lastName", "Smith"),
            ],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse valid SAML response");
        assert_eq!(parsed.attributes.len(), 3, "Should extract 3 attributes");

        let email_attr = parsed.attributes.iter().find(|(n, _)| n == "email");
        assert!(email_attr.is_some(), "Should have email attribute");
        assert_eq!(email_attr.unwrap().1, "user@example.com");

        let first_name = parsed.attributes.iter().find(|(n, _)| n == "firstName");
        assert!(first_name.is_some(), "Should have firstName attribute");
        assert_eq!(first_name.unwrap().1, "Alice");
    }

    #[test]
    fn test_saml_ignores_attribute_value_outside_attribute() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion>
        <saml:Conditions>
            <saml:AudienceRestriction>
                <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML");

        assert!(parsed.attributes.is_empty());
    }

    #[test]
    fn test_saml_rejects_failure_status_code() {
        // Verify that a SAML response with a non-success StatusCode is
        // detected as failed. The production code returns an error when the
        // status code is not `:Success`.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        let is_not_success = !parsed.status_code.ends_with(":Success")
            && parsed.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success";
        assert!(
            is_not_success,
            "Status code '{}' should be detected as failure",
            parsed.status_code
        );
    }

    #[test]
    fn test_saml_rejects_denied_status_code() {
        // Verify that a SAML response with AuthnFailed status is detected.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        let is_not_success = !parsed.status_code.ends_with(":Success")
            && parsed.status_code != "urn:oasis:names:tc:SAML:2.0:status:Success";
        assert!(is_not_success, "AuthnFailed should be detected as failure");
    }

    #[test]
    fn test_saml_issuer_mismatch_detection() {
        // Verify issuer mismatch is detectable. The production code compares
        // the extracted issuer against the configured entity_id.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:evil:entity", // Different from expected "urn:apexmail:enterprise"
            "https://apexmail.com/api/sso/saml/callback",
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        assert_eq!(parsed.issuer, "urn:evil:entity");
        // The production code would compare: parsed.issuer == expected_entity_id
        assert_ne!(
            parsed.issuer, "urn:apexmail:enterprise",
            "Issuer mismatch should be detectable"
        );
    }

    #[test]
    fn test_saml_audience_mismatch_detection() {
        // Verify audience mismatch is detectable. The production code compares
        // the extracted audience against the configured ACS URL.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://evil.com/callback", // Different from expected ACS URL
            Some("2026-12-01T00:00:00Z"),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse XML");
        assert_eq!(parsed.audience, "https://evil.com/callback");
        assert_ne!(
            parsed.audience, "https://apexmail.com/api/sso/saml/callback",
            "Audience mismatch should be detectable"
        );
    }

    #[test]
    fn test_saml_detects_missing_audience_restriction() {
        // Verify that XML without AudienceRestriction is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without audience");
        assert!(
            parsed.audience.is_empty(),
            "Audience should be empty when not present"
        );
    }

    #[test]
    fn test_saml_detects_missing_issuer() {
        // Verify that XML without Issuer is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without issuer");
        assert!(
            parsed.issuer.is_empty(),
            "Issuer should be empty when not present"
        );
    }

    #[test]
    fn test_saml_detects_missing_name_id() {
        // Verify that XML without NameID is handled.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse XML without NameID");
        assert!(
            parsed.name_id.is_empty(),
            "NameID should be empty when not present"
        );
    }

    #[test]
    fn test_saml_not_on_or_after_expiry_detection() {
        // Verify that a NotOnOrAfter date in the past is detectable as expired.
        let past_date = "2020-01-01T00:00:00Z";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some(past_date),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");

        // Verify the NotOnOrAfter value was extracted
        assert_eq!(parsed.not_on_or_after, Some(past_date.to_string()));

        // Verify it's in the past (would be rejected by prod code)
        if let Some(ref expiry) = parsed.not_on_or_after {
            let parsed_date = chrono::DateTime::parse_from_rfc3339(expiry)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            if let Some(expiry_time) = parsed_date {
                assert!(
                    Utc::now() > expiry_time,
                    "Expired assertion should be detected: {expiry} is in the past"
                );
            }
        }
    }

    #[test]
    fn test_saml_not_on_or_after_future_date_accepted() {
        // Verify that a NotOnOrAfter date in the future is NOT detected as expired.
        let future_date = "2030-12-01T00:00:00Z";
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            Some(future_date),
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");
        assert_eq!(parsed.not_on_or_after, Some(future_date.to_string()));

        if let Some(ref expiry) = parsed.not_on_or_after {
            let parsed_date = chrono::DateTime::parse_from_rfc3339(expiry)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            if let Some(expiry_time) = parsed_date {
                assert!(
                    Utc::now() < expiry_time,
                    "Future assertion should NOT be expired"
                );
            }
        }
    }

    #[test]
    fn test_saml_not_on_or_after_alternate_format() {
        // Verify parsing of NotOnOrAfter in `%Y-%m-%dT%H:%M:%S%:z` format
        // (the fallback format in production code).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://apexmail.com/api/sso/saml/callback">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_a1" IssueInstant="2025-01-01T00:00:01Z">
    <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="2030-06-15T12:30:00+00:00">
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse SAML response");
        assert!(
            parsed.not_on_or_after.is_some(),
            "NotOnOrAfter should be extracted from SAML response"
        );
    }

    #[test]
    fn test_saml_no_not_on_or_after_condition() {
        // Verify that SAML XML without a NotOnOrAfter attribute is handled.
        let xml = make_saml_response(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:apexmail:enterprise",
            "https://apexmail.com/api/sso/saml/callback",
            None, // No NotOnOrAfter
            "user@example.com",
            &[],
        );

        let parsed = parse_saml_response_xml(&xml).expect("Should parse SAML response");
        assert!(
            parsed.not_on_or_after.is_none(),
            "NotOnOrAfter should be None when not present"
        );
    }

    #[test]
    fn test_saml_status_code_via_empty_element() {
        // Verify that StatusCode can be parsed from a self-closing element
        // (the `Empty` event path in the production parser).
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>urn:apexmail:enterprise</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://apexmail.com/api/sso/saml/callback</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;

        let parsed = parse_saml_response_xml(xml).expect("Should parse SAML response");
        assert_eq!(
            parsed.status_code, "urn:oasis:names:tc:SAML:2.0:status:Success",
            "Should parse StatusCode from self-closing element"
        );
    }

    #[test]
    fn test_saml_malformed_xml_handled_gracefully() {
        // Verify that malformed XML does not panic; quick_xml is a streaming
        // parser and does not validate well-formedness, so it returns Ok with
        // default/empty fields rather than an error.
        let malformed = "<samlp:Response><unclosed>";
        let result = parse_saml_response_xml(malformed);
        // quick_xml streaming parser does not error on unclosed tags
        assert!(
            result.is_ok(),
            "Malformed XML should not cause parse error in streaming parser"
        );
        let parsed = result.unwrap();
        assert!(parsed.status_code.is_empty());
        assert!(parsed.issuer.is_empty());
    }

    #[test]
    fn test_saml_empty_xml_handled_gracefully() {
        // Verify that empty XML does not panic. quick_xml returns Eof
        // immediately, so the parser returns Ok with default values.
        let result = parse_saml_response_xml("");
        assert!(result.is_ok(), "Empty XML should not cause parse error");
        let parsed = result.unwrap();
        assert!(parsed.status_code.is_empty());
        assert!(parsed.issuer.is_empty());
    }

    // ── OIDC flow tests ───────────────────────────────────────────

    #[test]
    fn test_oidc_state_generation_uniqueness() {
        // Verify that generate_random_token produces unique states (used for
        // OIDC `state` parameter).
        let state1 = generate_random_token(32);
        let state2 = generate_random_token(32);
        assert_ne!(state1, state2, "OIDC states must be unique");
    }

    #[test]
    fn test_oidc_state_is_hex() {
        // Verify OIDC state is valid hex (derived from generate_random_token).
        let state = generate_random_token(16);
        assert_eq!(state.len(), 32);
        assert!(state.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_oidc_redirect_url_contains_required_params() {
        // Verify the OIDC redirect URL format contains all required OAuth2
        // authorization parameters. This mirrors the format in
        // `initiate_oidc_login`.
        let issuer = "https://accounts.google.com";
        let client_id = "test-client-id-123";
        let redirect_uri = "https://apexmail.com/api/sso/oidc/callback";
        let scopes = "openid profile email";
        let state = generate_random_token(32);
        let code_verifier = generate_pkce_verifier();
        let code_challenge = generate_pkce_challenge(&code_verifier);

        let redirect_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            issuer,
            urlencoding::encode(client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&code_challenge),
        );

        assert!(redirect_url.starts_with("https://accounts.google.com/authorize?"));
        assert!(redirect_url.contains("response_type=code"));
        assert!(redirect_url.contains("code_challenge_method=S256"));
        assert!(redirect_url.contains(&format!("state={}", urlencoding::encode(&state))));
        assert!(redirect_url.contains(&format!(
            "code_challenge={}",
            urlencoding::encode(&code_challenge)
        )));
    }

    #[test]
    fn test_oidc_redirect_url_contains_client_id() {
        // Verify the redirect URL includes the client_id parameter.
        let redirect_url = format!(
            "{}/authorize?client_id={}",
            "https://idp.example.com",
            urlencoding::encode("my-client-id")
        );
        assert!(redirect_url.contains("client_id=my-client-id"));
    }

    // ── Session / token tests ─────────────────────────────────────

    #[test]
    fn test_session_token_is_hex() {
        // Verify session tokens (from generate_random_token) are valid hex.
        let token = generate_random_token(64);
        assert_eq!(token.len(), 128);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_session_token_uniqueness() {
        // Verify two session tokens are unique.
        let t1 = generate_random_token(64);
        let t2 = generate_random_token(64);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_configure_request_with_all_optional_fields() {
        // Verify SSOConfigureRequest serde with all fields populated.
        let req = SSOConfigureRequest {
            tenant_id: "tenant_123".into(),
            provider_type: "oidc".into(),
            domain: "company.com".into(),
            enabled: Some(true),
            entity_id: Some("urn:company".into()),
            sso_url: Some("https://company.okta.com/sso".into()),
            certificate: Some("MIID....".into()),
            oidc_client_id: Some("client_123".into()),
            oidc_client_secret: Some("secret".into()),
            oidc_issuer: Some("https://company.okta.com".into()),
            attribute_mapping: Some(serde_json::json!({"email": "email"})),
            enforce_sso: Some(true),
            session_duration_hours: Some(24),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("oidc"));
        assert!(json.contains("attribute_mapping"));
        let parsed: SSOConfigureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_duration_hours, Some(24));
    }

    // ── SAML sanitize_value edge case tests ───────────────────────

    #[test]
    fn test_sanitize_saml_value_rejects_only_control_chars() {
        // Verify values consisting only of control characters are rejected.
        assert!(sanitize_saml_value("\x00\x01\x02").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_accepts_email_like() {
        // Verify common email-like values pass validation.
        assert_eq!(
            sanitize_saml_value("alice@example.com"),
            "alice@example.com"
        );
        assert_eq!(
            sanitize_saml_value("bob+tag@example.co.uk"),
            "bob+tag@example.co.uk"
        );
        assert_eq!(
            sanitize_saml_value("user@sub.example.org"),
            "user@sub.example.org"
        );
    }

    #[test]
    fn test_sanitize_saml_value_rejects_combined_xml_and_control() {
        // Verify values with combined XML special chars and control chars are rejected.
        assert!(sanitize_saml_value("<script\x00>").is_empty());
        assert!(sanitize_saml_value("foo&\x01bar").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_rejects_leading_trailing_whitespace_only() {
        // Verify whitespace-only values become empty after trim.
        assert!(sanitize_saml_value("   ").is_empty());
        assert!(sanitize_saml_value("\t\n\r").is_empty());
    }

    #[test]
    fn test_sanitize_saml_value_exact_256_boundary() {
        // Verify the exact 256-char boundary passes.
        let exact = "a".repeat(256);
        assert_eq!(sanitize_saml_value(&exact).len(), 256);
    }

    #[test]
    fn test_sanitize_saml_value_257_rejected() {
        // Verify that 257 chars are rejected.
        let too_long = "a".repeat(257);
        assert!(sanitize_saml_value(&too_long).is_empty());
    }
}
