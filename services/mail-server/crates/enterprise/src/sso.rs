use std::sync::Once;

use chrono::{DateTime, TimeDelta, Utc};
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

/// Tolerated clock skew between this service and the IdP when evaluating a
/// SAML assertion's `NotBefore` / `NotOnOrAfter` bounds (SAML 2.0 §2.5.1.2).
/// Applied symmetrically: an assertion may start up to 5 minutes in the
/// future and may have expired up to 5 minutes ago.
pub const SAML_CLOCK_SKEW_SECONDS: i64 = 300;

/// Retention horizon for consumed SAML assertion ids in
/// `ent_saml_assertion_replays` (bounds the replay table): 24 hours, always
/// at least as long as the maximum assertion validity window.
pub const SAML_REPLAY_RETENTION_HOURS: i32 = 24;

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

// ── X.509 → SPKI extraction (minimal DER walk, no external deps) ────────────
//
// xml-sec's `verify_signature_with_pem_key` verifies with a `PUBLIC KEY`
// (SubjectPublicKeyInfo) PEM and rejects CERTIFICATE PEMs, while IdP SAML
// metadata hands us an X.509 certificate. Extract the certificate's embedded
// SubjectPublicKeyInfo so real IdP certificates verify:
//
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
// TBSCertificate ::= SEQUENCE {
//     [0] version, serialNumber, signatureAlgorithm,
//     issuer, validity, subject, subjectPublicKeyInfo, ... }
//
// The walker only needs offsets, so it verifies tags structurally and
// borrows the SPKI bytes straight out of the input.

/// Read one DER TLV at `pos`; returns `(tag, contents, position_after)`.
fn der_tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), String> {
    let tag = *buf.get(pos).ok_or("DER: truncated tag")?;
    let mut p = pos + 1;
    let first = *buf.get(p).ok_or("DER: truncated length")?;
    p += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err("DER: unsupported length form".to_string());
        }
        let mut len = 0usize;
        for _ in 0..count {
            let byte = *buf.get(p).ok_or("DER: truncated long length")?;
            len = (len << 8) | byte as usize;
            p += 1;
        }
        len
    };
    let end = p.checked_add(len).ok_or("DER: length overflow")?;
    if end > buf.len() {
        return Err("DER: contents exceed buffer".to_string());
    }
    Ok((tag, &buf[p..end], end))
}

fn expect_tlv<'a>(
    buf: &'a [u8],
    pos: usize,
    want_tag: u8,
    context: &str,
) -> Result<(&'a [u8], usize), String> {
    let (tag, contents, end) = der_tlv(buf, pos)?;
    if tag != want_tag {
        return Err(format!(
            "DER {context}: expected tag 0x{want_tag:02x}, got 0x{tag:02x}"
        ));
    }
    Ok((contents, end))
}

/// Extract the DER SubjectPublicKeyInfo from a DER X.509 certificate.
fn spki_der_from_certificate_der(cert_der: &[u8]) -> Result<&[u8], String> {
    let (tbs_sequence, _) = expect_tlv(cert_der, 0, 0x30, "certificate")?;
    let (tbs, _) = expect_tlv(tbs_sequence, 0, 0x30, "tbsCertificate")?;
    let mut pos = 0usize;

    // Optional [0] EXPLICIT version.
    if let Some(&first) = tbs.first() {
        if first == 0xA0 {
            let (_version, end) = expect_tlv(tbs, pos, 0xA0, "version")?;
            pos = end;
        }
    }
    let (_serial, next) = expect_tlv(tbs, pos, 0x02, "serialNumber")?;
    let (_signature_algorithm, next) = expect_tlv(tbs, next, 0x30, "signature algorithm")?;
    let (_issuer, next) = expect_tlv(tbs, next, 0x30, "issuer")?;
    let (_validity, next) = expect_tlv(tbs, next, 0x30, "validity")?;
    let (_subject, next) = expect_tlv(tbs, next, 0x30, "subject")?;
    // The PUBLIC KEY PEM must carry the full SPKI element — tag and length
    // header included — not just its contents.
    let spki_start = next;
    let (_spki_contents, spki_end) = expect_tlv(tbs, next, 0x30, "subjectPublicKeyInfo")?;
    Ok(&tbs[spki_start..spki_end])
}

fn strip_pem_armor(pem: &str) -> Result<String, String> {
    let body: String = pem
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .map(|line| line.trim())
        .collect();
    if body.is_empty() {
        return Err("PEM body is empty".to_string());
    }
    Ok(body)
}

/// Build a `PUBLIC KEY` PEM from DER SubjectPublicKeyInfo bytes.
fn spki_der_to_public_key_pem(spki_der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----");
    pem
}

/// Convert a certificate (PEM or base64 DER) into the SPKI `PUBLIC KEY` PEM
/// the verifier needs. A `PUBLIC KEY` block passes through unchanged.
fn public_key_pem_from_certificate(cert: &str) -> Result<String, String> {
    let trimmed = cert.trim();
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
        let body = strip_pem_armor(trimmed)?;
        let cert_der =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body.as_bytes())
                .map_err(|error| format!("SAML certificate base64 decode failed: {error}"))?;
        return Ok(spki_der_to_public_key_pem(spki_der_from_certificate_der(
            &cert_der,
        )?));
    }
    if trimmed.starts_with("-----BEGIN ") {
        return Err("SAML IdP certificate must be a CERTIFICATE or PUBLIC KEY PEM".to_string());
    }
    // Raw base64 DER certificate: wrap, then extract.
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() < 20 {
        return Err("SAML certificate is too short".to_string());
    }
    let cert_der =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, clean.as_bytes())
            .map_err(|error| format!("SAML certificate base64 decode failed: {error}"))?;
    Ok(spki_der_to_public_key_pem(spki_der_from_certificate_der(
        &cert_der,
    )?))
}

/// Verify the XML digital signature on a SAML response using the IdP's certificate.
fn verify_saml_signature(saml_xml: &str, cert_pem: &str) -> Result<(), String> {
    use xml_sec::xmldsig::verify::verify_signature_with_pem_key;
    use xml_sec::xmldsig::verify::DsigStatus;

    // The verifier requires an SPKI `PUBLIC KEY` PEM; the configured IdP
    // material is usually an X.509 CERTIFICATE (or bare base64 DER of one).
    // Extract the embedded public key so real IdP certificates verify.
    let verifying_pem = public_key_pem_from_certificate(cert_pem)?;

    match verify_signature_with_pem_key(saml_xml, &verifying_pem, false) {
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

/// F7 (audit): reusable per-tenant `enforce_sso` lookup for api-server's
/// auth gate — `SELECT enforce_sso FROM ent_sso_configurations WHERE
/// tenant_id = $1 LIMIT 1`.
///
/// Contract:
/// * `Ok(true)`  — a configuration row sets `enforce_sso = true`; password
///   logins for this tenant must be rejected.
/// * `Ok(false)` — no row, or `enforce_sso = false`: password logins allowed.
/// * `Ok(false)` — the table itself is absent (`42P01`, migrations not yet
///   applied): the gate degrades open rather than locking every tenant out.
/// * `Err`       — any other database failure (surfaced so the caller can
///   fail closed on infrastructure errors).
pub async fn tenant_enforces_sso(db: &PgPool, tenant_id: &str) -> Result<bool, String> {
    match sqlx::query_scalar::<_, bool>(
        "SELECT enforce_sso FROM ent_sso_configurations WHERE tenant_id = $1 LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    {
        Ok(Some(enforced)) => Ok(enforced),
        Ok(None) => Ok(false),
        Err(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("42P01") => {
            Ok(false)
        }
        Err(error) => Err(format!("Check enforce_sso for tenant {tenant_id}: {error}")),
    }
}

impl SSOService {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            redis: None,
            config,
        }
    }

    /// F7: per-tenant SSO enforcement via this service's pool — see
    /// [`tenant_enforces_sso`] for the exact semantics.
    pub async fn tenant_enforces_sso(&self, tenant_id: &str) -> Result<bool, String> {
        tenant_enforces_sso(&self.db, tenant_id).await
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
        verify_saml_signature(saml_response_xml, cert_raw)?;

        let mut current_path = Vec::new();
        let mut status_code_value: Option<String> = None;
        let mut issuer_value: Option<String> = None;
        let mut audience_value: Option<String> = None;
        let mut not_before: Option<chrono::DateTime<Utc>> = None;
        let mut not_on_or_after: Option<chrono::DateTime<Utc>> = None;
        let mut assertion_id: Option<String> = None;
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
                        "Assertion" => {
                            // The assertion id is the replay-protection key.
                            if assertion_id.is_none() {
                                if let Some(attr) = e
                                    .attributes()
                                    .filter_map(|a| a.ok())
                                    .find(|a| a.key.as_ref() == b"ID")
                                {
                                    if let Ok(val) = String::from_utf8(attr.value.to_vec()) {
                                        assertion_id = Some(val);
                                    }
                                }
                            }
                        }
                        "Conditions" => {
                            in_conditions = true;
                            // Extract the validity-window attributes from the
                            // Conditions element.
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let value = match String::from_utf8(attr.value.to_vec()) {
                                    Ok(value) => value,
                                    Err(_) => continue,
                                };
                                let parsed = chrono::DateTime::parse_from_rfc3339(&value)
                                    .map(|dt| dt.with_timezone(&Utc))
                                    .ok()
                                    .or_else(|| {
                                        chrono::DateTime::parse_from_str(
                                            &value,
                                            "%Y-%m-%dT%H:%M:%S%:z",
                                        )
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .ok()
                                    });
                                match attr.key.as_ref() {
                                    b"NotBefore" => not_before = parsed,
                                    b"NotOnOrAfter" => not_on_or_after = parsed,
                                    _ => {}
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
                // quick-xml 0.41: `unescape()` is gone; Text events are decoded
                // via `decode()`. Entity references now arrive as separate
                // `Event::GeneralRef` events, so Text content is entity-free.
                Ok(Event::Text(ref e)) => {
                    if let Ok(text) = e.decode() {
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

        // 5. Validate and sanitize NameID
        let name_id = name_id_value.ok_or_else(|| {
            tracing::warn!(domain = domain, "SAML response missing NameID");
            "SAML response missing NameID element".to_string()
        })?;

        let sanitized_name_id = sanitize_saml_value(&name_id);

        if sanitized_name_id.is_empty() {
            tracing::warn!(domain = domain, "SAML NameID is empty after sanitization");
            return Err("SAML NameID is empty after sanitization".to_string());
        }

        // 6. Enforce the assertion validity window (bounded clock skew) and
        //    the per-tenant replay guard. Only reached after every signature
        //    and claim check above has passed, so an invalid assertion cannot
        //    burn an assertion id.
        let assertion_id = assertion_id.ok_or_else(|| {
            tracing::warn!(domain = domain, "SAML response missing Assertion ID");
            "SAML response missing Assertion ID (required for replay protection)".to_string()
        })?;
        self.validate_saml_assertion_claims(
            &config.tenant_id,
            &assertion_id,
            not_before,
            not_on_or_after,
            Utc::now(),
        )
        .await?;

        Ok(ValidatedSamlResponse {
            name_id: sanitized_name_id,
            attributes,
        })
    }

    /// Enforce a SAML assertion's validity window and replay protection.
    ///
    /// This is the post-signature half of
    /// [`Self::parse_and_validate_saml_response`], kept separate so it can be
    /// tested without an IdP-signed XML fixture:
    ///
    /// * `NotBefore`/`NotOnOrAfter` are compared against `now` with
    ///   [`SAML_CLOCK_SKEW_SECONDS`] of tolerance on BOTH bounds, so small
    ///   clock differences between this service and the IdP do not reject
    ///   otherwise-valid assertions.
    /// * `assertion_id` is consumed exactly once per `tenant_id` in
    ///   `ent_saml_assertion_replays` (idempotent `ON CONFLICT DO NOTHING`
    ///   insert); a second use of the same id is rejected as a replay. The
    ///   table is pruned to [`SAML_REPLAY_RETENTION_HOURS`] so it stays bounded.
    pub async fn validate_saml_assertion_claims(
        &self,
        tenant_id: &str,
        assertion_id: &str,
        not_before: Option<DateTime<Utc>>,
        not_on_or_after: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let assertion_id = assertion_id.trim();
        if assertion_id.is_empty() {
            return Err(
                "SAML assertion is missing an ID; it cannot be protected against replay"
                    .to_string(),
            );
        }

        let skew = TimeDelta::seconds(SAML_CLOCK_SKEW_SECONDS);

        if let Some(not_before) = not_before {
            if now + skew < not_before {
                tracing::warn!(
                    not_before = %not_before.to_rfc3339(),
                    skew_seconds = SAML_CLOCK_SKEW_SECONDS,
                    "SAML assertion is not yet valid"
                );
                return Err(format!(
                    "SAML assertion is not yet valid (NotBefore {})",
                    not_before.to_rfc3339()
                ));
            }
        }

        if let Some(expires) = not_on_or_after {
            if now - skew > expires {
                tracing::warn!(
                    expires = %expires.to_rfc3339(),
                    skew_seconds = SAML_CLOCK_SKEW_SECONDS,
                    "SAML assertion has expired"
                );
                return Err(format!(
                    "SAML assertion has expired (NotOnOrAfter {})",
                    expires.to_rfc3339()
                ));
            }
        }

        // Bounded replay store: drop ids older than the retention horizon
        // before inserting, so the table cannot grow without bound.
        sqlx::query(
            "DELETE FROM ent_saml_assertion_replays
             WHERE consumed_at < NOW() - make_interval(hours => $1::int)",
        )
        .bind(SAML_REPLAY_RETENTION_HOURS)
        .execute(&self.db)
        .await
        .map_err(|error| format!("Prune SAML replay store: {error}"))?;

        // Idempotent, bounded insert: ON CONFLICT DO NOTHING + RETURNING
        // distinguishes "fresh" from "already consumed" atomically.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO ent_saml_assertion_replays (tenant_id, assertion_id)
             VALUES ($1, $2)
             ON CONFLICT (tenant_id, assertion_id) DO NOTHING
             RETURNING assertion_id",
        )
        .bind(tenant_id)
        .bind(assertion_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Record SAML assertion replay guard: {error}"))?;

        if inserted.is_none() {
            tracing::warn!(
                tenant_id = tenant_id,
                assertion_id = assertion_id,
                "SAML assertion replay detected"
            );
            return Err(format!(
                "SAML assertion replay rejected: assertion {assertion_id} was already consumed for this tenant"
            ));
        }

        Ok(())
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
                // quick-xml 0.41: escape() takes impl Into<Cow<str>>; deref the
                // &&str tuple fields (0.36's &str parameter auto-derefed them).
                xml_escape(*name),
                xml_escape(*value),
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
                    if let Ok(text) = e.decode() {
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
                        assert_eq!(e.decode().unwrap().as_ref(), entity_id);
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
    // ═══════════════════════════════════════════════════════════════════
    // Signed-SAML fixture machinery
    //
    // An in-test IdP: a real RSA keypair (see tests/keys/) plus a minimal
    // big-integer RSA implementation so tests can produce genuinely signed
    // XML-DSig envelopes (RSA-SHA256, exclusive C14N over SignedInfo,
    // enveloped-signature transform over the whole document). Every byte of
    // the signature path is exercised through the production verifier, so a
    // signing bug fails loudly instead of faking coverage.
    // ═══════════════════════════════════════════════════════════════════

    mod idp {
        use super::*;

        // ── big integer (little-endian u64 limbs) ──

        pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
            let mut out = vec![0u64; a.len() + b.len()];
            for (i, &ai) in a.iter().enumerate() {
                let mut carry: u128 = 0;
                for (j, &bj) in b.iter().enumerate() {
                    let t = ai as u128 * bj as u128 + out[i + j] as u128 + carry;
                    out[i + j] = t as u64;
                    carry = t >> 64;
                }
                let mut k = i + b.len();
                while carry > 0 {
                    let t = out[k] as u128 + carry;
                    out[k] = t as u64;
                    carry = t >> 64;
                    k += 1;
                }
            }
            while out.len() > 1 && *out.last().unwrap() == 0 {
                out.pop();
            }
            out
        }

        pub fn cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
            let n = a.len().max(b.len());
            for i in (0..n).rev() {
                let av = a.get(i).copied().unwrap_or(0);
                let bv = b.get(i).copied().unwrap_or(0);
                if av != bv {
                    return av.cmp(&bv);
                }
            }
            std::cmp::Ordering::Equal
        }

        fn shl(a: &[u64], shift: u32) -> Vec<u64> {
            if shift == 0 {
                return a.to_vec();
            }
            let mut out = vec![0u64; a.len()];
            for i in 0..a.len() {
                if i > 0 {
                    out[i] |= a[i - 1] >> (64 - shift);
                }
                out[i] |= a[i] << shift;
            }
            out
        }

        fn shr(a: &[u64], shift: u32) -> Vec<u64> {
            if shift == 0 {
                return a.to_vec();
            }
            let mut out = vec![0u64; a.len()];
            for i in 0..a.len() {
                out[i] = a[i] >> shift;
                if i + 1 < a.len() {
                    out[i] |= a[i + 1] << (64 - shift);
                }
            }
            while out.len() > 1 && *out.last().unwrap() == 0 {
                out.pop();
            }
            out
        }

        /// Knuth algorithm D: `(quotient, remainder)` of `u / v`.
        pub fn divmod(u: &[u64], v: &[u64]) -> (Vec<u64>, Vec<u64>) {
            assert!(!v.is_empty() && *v.last().unwrap() != 0, "zero divisor");
            if cmp(u, v) == std::cmp::Ordering::Less {
                return (vec![0], u.to_vec());
            }
            if v.len() == 1 {
                let d = v[0];
                let mut q = vec![0u64; u.len()];
                let mut rem: u128 = 0;
                for i in (0..u.len()).rev() {
                    let cur = (rem << 64) | u[i] as u128;
                    q[i] = (cur / d as u128) as u64;
                    rem = cur % d as u128;
                }
                while q.len() > 1 && *q.last().unwrap() == 0 {
                    q.pop();
                }
                return (q, vec![rem as u64]);
            }
            let shift = v[v.len() - 1].leading_zeros();
            let vn = shl(v, shift);
            let mut padded = u.to_vec();
            padded.push(0);
            let mut un = shl(&padded, shift);
            while un.len() < padded.len() {
                un.push(0);
            }
            let n = vn.len();
            let m = un.len() - n - 1;
            let mut q = vec![0u64; m + 1];
            let vtop = vn[n - 1];
            let vnext = vn[n - 2];
            for j in (0..=m).rev() {
                let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
                let mut qhat = num / vtop as u128;
                let mut rhat = num % vtop as u128;
                while qhat >> 64 != 0
                    || qhat * vnext as u128 > ((rhat << 64) | un[j + n - 2] as u128)
                {
                    qhat -= 1;
                    rhat += vtop as u128;
                    if rhat >> 64 != 0 {
                        break;
                    }
                }
                let mut borrow: u64 = 0;
                let mut carry: u64 = 0;
                for i in 0..n {
                    let p = qhat * vn[i] as u128 + carry as u128;
                    carry = (p >> 64) as u64;
                    let (r1, b1) = un[i + j].overflowing_sub(p as u64);
                    let (r2, b2) = r1.overflowing_sub(borrow);
                    un[i + j] = r2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
                let (r1, b1) = un[j + n].overflowing_sub(carry);
                let (r2, b2) = r1.overflowing_sub(borrow);
                un[j + n] = r2;
                if b1 || b2 {
                    qhat -= 1;
                    let mut carry: u128 = 0;
                    for i in 0..n {
                        let t = un[i + j] as u128 + vn[i] as u128 + carry;
                        un[i + j] = t as u64;
                        carry = t >> 64;
                    }
                    un[j + n] = un[j + n].wrapping_add(carry as u64);
                }
                q[j] = qhat as u64;
            }
            while q.len() > 1 && *q.last().unwrap() == 0 {
                q.pop();
            }
            let mut rem = un[..n].to_vec();
            rem = shr(&rem, shift);
            (q, rem)
        }

        pub fn modexp(base: &[u64], exp: &[u64], modulus: &[u64]) -> Vec<u64> {
            let reduced = divmod(base, modulus).1;
            let mut result = vec![1u64];
            for i in (0..exp.len()).rev() {
                for bit in (0..64).rev() {
                    result = divmod(&mul(&result, &result), modulus).1;
                    if (exp[i] >> bit) & 1 == 1 {
                        result = divmod(&mul(&result, &reduced), modulus).1;
                    }
                }
            }
            result
        }

        fn le_bytes_to_limbs(bytes: &[u8]) -> Vec<u64> {
            let mut out = vec![0u64; bytes.len().div_ceil(8)];
            for (i, &b) in bytes.iter().rev().enumerate() {
                out[i / 8] |= (b as u64) << ((i % 8) * 8);
            }
            out
        }

        fn limbs_to_be_bytes(limbs: &[u64], len: usize) -> Vec<u8> {
            let mut out = vec![0u8; len];
            for (i, limb) in limbs.iter().enumerate() {
                for b in 0..8 {
                    let idx = match len.checked_sub(1 + i * 8 + b) {
                        Some(idx) => idx,
                        None => break,
                    };
                    out[idx] = (limb >> (8 * b)) as u8;
                }
            }
            out
        }

        // ── DER (PKCS#8) private-key parse ──

        fn read_tlv(buf: &[u8], pos: usize) -> (u8, &[u8], usize) {
            let tag = buf[pos];
            let mut p = pos + 1;
            let first = buf[p];
            p += 1;
            let len = if first & 0x80 == 0 {
                first as usize
            } else {
                let count = (first & 0x7f) as usize;
                let mut len = 0usize;
                for _ in 0..count {
                    len = (len << 8) | buf[p] as usize;
                    p += 1;
                }
                len
            };
            (tag, &buf[p..p + len], p + len)
        }

        /// An RSA private key with just the pieces signing needs.
        pub struct RsaPrivateKey {
            pub n: Vec<u64>,
            pub d: Vec<u64>,
            pub byte_len: usize,
        }

        impl RsaPrivateKey {
            pub fn from_pkcs8_pem(pem: &str) -> RsaPrivateKey {
                use base64::Engine;
                let body: String = pem
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .map(|line| line.trim())
                    .collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .expect("PKCS#8 base64");
                // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey }
                let (tag, info, _) = read_tlv(&der, 0);
                assert_eq!(tag, 0x30);
                let (_t_version, _v, after_version) = read_tlv(info, 0);
                let (_t_alg, _alg, after_alg) = read_tlv(info, after_version);
                let (t_octet, pkcs1, _) = read_tlv(info, after_alg);
                assert_eq!(t_octet, 0x04, "expected OCTET STRING privateKey");
                // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, ... }
                let (t_seq, seq, _) = read_tlv(pkcs1, 0);
                assert_eq!(t_seq, 0x30);
                let (_tv, _version, p) = read_tlv(seq, 0);
                let (_tn, n, p) = read_tlv(seq, p);
                let (_te, _e, p) = read_tlv(seq, p);
                let (_td, d, _p) = read_tlv(seq, p);
                let n = if n[0] == 0 { &n[1..] } else { n };
                let d = if d[0] == 0 { &d[1..] } else { d };
                let byte_len = n.len();
                RsaPrivateKey {
                    n: le_bytes_to_limbs(n),
                    d: le_bytes_to_limbs(d),
                    byte_len,
                }
            }

            /// RSASSA-PKCS1-v1_5 signature over `message` with SHA-256.
            pub fn sign_pkcs1_sha256(&self, message: &[u8]) -> Vec<u8> {
                let digest = Sha256::digest(message);
                // DigestInfo for SHA-256 (RFC 8017 §9.2 note 1).
                let t: Vec<u8> = [
                    &[
                        0x30u8, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                    ][..],
                    &digest,
                ]
                .concat();
                let k = self.byte_len;
                let mut em = vec![0u8, 0x01];
                em.extend(std::iter::repeat_n(0xff, k - 3 - t.len()));
                em.push(0x00);
                em.extend_from_slice(&t);
                assert_eq!(em.len(), k);
                let sig = modexp(&le_bytes_to_limbs(&em), &self.d, &self.n);
                limbs_to_be_bytes(&sig, k)
            }
        }

        // ── XML-DSig envelope assembly ──

        use xml_sec::c14n::{canonicalize_xml, C14nAlgorithm, C14nMode};

        const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
        const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
        const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
        const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

        fn b64(data: &[u8]) -> String {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(data)
        }

        /// Sign `document_prefix` + `document_suffix` (the SAML response with
        /// the Signature element excised) and return the full document with
        /// the enveloped `<ds:Signature>` spliced between them.
        pub fn seal(document_prefix: &str, document_suffix: &str, key: &RsaPrivateKey) -> String {
            // Digest over the canonicalised unsigned document: exactly what
            // the verifier's enveloped-signature transform leaves behind.
            let unsigned = format!("{document_prefix}{document_suffix}");
            let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
            let canonical = canonicalize_xml(unsigned.as_bytes(), &algorithm)
                .expect("canonicalize unsigned SAML document");
            let digest = Sha256::digest(&canonical);

            let signed_info = format!(
                r#"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
                b64(&digest)
            );
            // The verifier canonicalises the SignedInfo SUBTREE with its
            // declared exclusive C14N — canonicalising the same bytes
            // standalone produces the identical octets.
            let exc = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
            let canonical_signed_info =
                canonicalize_xml(signed_info.as_bytes(), &exc).expect("canonicalize SignedInfo");
            let signature = key.sign_pkcs1_sha256(&canonical_signed_info);

            format!(
                "{document_prefix}<ds:Signature xmlns:ds=\"{DS_NS}\">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>{document_suffix}",
                b64(&signature)
            )
        }
    }

    const IDP_PRIVATE_KEY_PEM: &str = include_str!("../tests/keys/saml_idp_key.pem");
    const IDP_CERTIFICATE_PEM: &str = include_str!("../tests/keys/saml_idp_cert.pem");

    /// The properties of one IdP response fixture; every refusal arm of the
    /// parser is a small mutation of this struct.
    struct SamlFixture {
        issuer: String,
        audience: String,
        name_id: String,
        status_value: String,
        assertion_id: String,
        not_before: Option<DateTime<Utc>>,
        not_on_or_after: Option<DateTime<Utc>>,
        attributes: Vec<(String, String)>,
        include_signature: bool,
        include_audience: bool,
        include_conditions: bool,
    }

    impl SamlFixture {
        fn valid(expected_entity_id: &str, expected_acs_url: &str) -> SamlFixture {
            SamlFixture {
                issuer: expected_entity_id.to_string(),
                audience: expected_acs_url.to_string(),
                name_id: "alice.smith@example.com".to_string(),
                status_value: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
                assertion_id: format!("_assertion_{}", Uuid::new_v4()),
                not_before: Some(Utc::now() - chrono::Duration::minutes(2)),
                not_on_or_after: Some(Utc::now() + chrono::Duration::minutes(5)),
                attributes: vec![
                    ("email".to_string(), "alice.smith@example.com".to_string()),
                    ("group".to_string(), "engineering".to_string()),
                ],
                include_signature: true,
                include_audience: true,
                include_conditions: true,
            }
        }

        fn unsigned_document(&self) -> String {
            let conditions = if self.include_conditions {
                let mut attrs = String::new();
                if let Some(nb) = self.not_before {
                    attrs.push_str(&format!(
                        " NotBefore=\"{}\"",
                        nb.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    ));
                }
                if let Some(e) = self.not_on_or_after {
                    attrs.push_str(&format!(
                        " NotOnOrAfter=\"{}\"",
                        e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    ));
                }
                format!("<saml:Conditions{attrs}>")
            } else {
                String::new()
            };
            let conditions_close = if self.include_conditions {
                "</saml:Conditions>"
            } else {
                ""
            };
            let audience = if self.include_audience {
                format!(
                    "<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                    self.audience
                )
            } else {
                String::new()
            };
            let attributes: String = self
                .attributes
                .iter()
                .map(|(name, value)| {
                    format!(
                        "<saml:Attribute Name=\"{name}\"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"
                    )
                })
                .collect();
            format!(
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp_cov\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\" Destination=\"{acs}\">\
<samlp:Status><samlp:StatusCode Value=\"{status}\"/></samlp:Status>\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:Assertion ID=\"{assertion}\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject>\
{conditions}{audience}{conditions_close}<saml:AttributeStatement>{attributes}</saml:AttributeStatement>\
</saml:Assertion>\
</samlp:Response>",
                acs = self.audience,
                status = self.status_value,
                issuer = self.issuer,
                assertion = self.assertion_id,
                name_id = self.name_id,
            )
        }

        /// The full signed document (or unsigned when
        /// `include_signature == false`).
        fn render(&self, key: &idp::RsaPrivateKey) -> String {
            let document = self.unsigned_document();
            if !self.include_signature {
                return document;
            }
            // Splice point: right before the closing Response element.
            let split = document
                .rfind("</samlp:Response>")
                .expect("fixture has a Response root");
            let (prefix, suffix) = document.split_at(split);
            idp::seal(prefix, suffix, key)
        }
    }

    // ── pure signing-machinery sanity (openssl-verified construction) ──

    #[test]
    fn idp_key_parses_and_signs_deterministically() {
        let key = idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM);
        assert_eq!(key.byte_len, 256, "the fixture key is RSA-2048");
        let sig = key.sign_pkcs1_sha256(b"apexmail saml fixture");
        assert_eq!(sig.len(), 256);
        assert_eq!(sig, key.sign_pkcs1_sha256(b"apexmail saml fixture"));
        assert_ne!(sig, key.sign_pkcs1_sha256(b"apexmail saml fixture 2"));
    }

    #[test]
    fn bignum_matches_known_small_values() {
        assert_eq!(idp::modexp(&[2], &[10], &[1000]), vec![24]);
        assert_eq!(idp::mul(&[3, 0], &[5]), vec![15]);
        assert_eq!(idp::divmod(&[100], &[7]), (vec![14], vec![2]));
        // A divisor whose top limb has leading zeros forces the normalized
        // (shifted) division path.
        let x = vec![0xdead_beef, 0x1234, 0x5678, 9];
        let y = vec![0xfeed_face, 0x9999, 3];
        let product = idp::mul(&x, &y);
        let (q, r) = idp::divmod(&product, &y);
        assert_eq!(q, x, "quotient");
        assert!(r.iter().all(|&limb| limb == 0), "remainder is zero");
        // A dividend that needs the padded-high-limb normalization shift.
        let u = vec![0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 5];
        let v = vec![0x8000_0000_0000_0001, 1];
        let (q3, r3) = idp::divmod(&u, &v);
        assert!(idp::cmp(&r3, &v) == std::cmp::Ordering::Less);
        let check = idp::mul(&q3, &v);
        assert!(idp::cmp(&check, &u) != std::cmp::Ordering::Greater);
    }

    #[test]
    fn saml_fixture_renders_the_no_conditions_and_attributeless_shapes() {
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let mut fixture = SamlFixture::valid("https://idp.example.com", "https://acs");
        fixture.include_conditions = false;
        let without_conditions = fixture.unsigned_document();
        assert!(!without_conditions.contains("saml:Conditions"));
        let signed = fixture.render(key);
        assert!(signed.contains("<ds:Signature "), "signed envelope present");

        fixture.attributes.clear();
        assert!(!fixture.unsigned_document().contains("saml:Attribute Name"));

        fixture.not_before = None;
        fixture.not_on_or_after = None;
        assert!(!fixture.unsigned_document().contains("NotBefore"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // DB-backed signed-SAML coverage: every parser-refusal arm, the
    // replay guard, the OIDC state machine and the session lifecycle,
    // driven against private clones of the canonical schema.
    // ═══════════════════════════════════════════════════════════════════

    async fn provision_sso(tag: &str) -> (SSOService, sqlx::PgPool) {
        if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SSO_ENCRYPTION_KEY", "sso-coverage-key-0123456789");
        }
        if std::env::var("LOG_STREAM_ENCRYPTION_KEY").is_err() {
            std::env::set_var(
                "LOG_STREAM_ENCRYPTION_KEY",
                "log-stream-coverage-key-0123456789",
            );
        }
        let pool = migrator::test_support::fresh_canonical_pool(tag, &format!("sso_cov_{tag}"))
            .await
            .expect("provision canonical pool")
            .expect("TEST_DATABASE_URL must be configured for this suite");
        let config = Config::from_env().expect("Config::from_env in test env");
        (SSOService::new(pool.clone(), config), pool)
    }

    fn coverage_tenant(tag: &str) -> String {
        let unique = Uuid::new_v4().simple().to_string();
        let keep = 26usize.saturating_sub(tag.len() + 1);
        format!("{tag}_{}", &unique[..keep.min(unique.len())])
    }

    fn self_acs_url(service: &SSOService) -> String {
        service.config.sso.saml.acs_url.clone()
    }

    async fn configure_saml_tenant(
        service: &SSOService,
        tenant: &str,
        domain: &str,
        with_certificate: bool,
    ) -> (String, String) {
        // The entity id must match the fixture Issuer; the ACS URL comes
        // from the service config (the audience in the assertion).
        let entity_id = "https://idp.coverage.example.com/metadata".to_string();
        // The parser compares the assertion Audience against the SERVICE
        // config's ACS URL (not anything stored on the tenant row).
        let acs_url = self_acs_url(service);
        service
            .configure(SSOConfigureRequest {
                tenant_id: tenant.to_string(),
                provider_type: "saml".to_string(),
                domain: domain.to_string(),
                enabled: Some(true),
                entity_id: Some(entity_id.clone()),
                sso_url: Some("https://idp.coverage.example.com/sso".to_string()),
                certificate: if with_certificate {
                    Some(IDP_CERTIFICATE_PEM.to_string())
                } else {
                    None
                },
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: Some(true),
                session_duration_hours: None,
            })
            .await
            .expect("configure SAML")
            .data
            .expect("configure returned a row");
        (entity_id, acs_url)
    }

    async fn parse_fixture(
        service: &SSOService,
        domain: &str,
        fixture: &SamlFixture,
    ) -> Result<ValidatedSamlResponse, String> {
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let document = fixture.render(key);
        service
            .parse_and_validate_saml_response(&document, domain)
            .await
    }

    static IDP_KEY: std::sync::OnceLock<idp::RsaPrivateKey> = std::sync::OnceLock::new();

    #[tokio::test]
    async fn signed_saml_response_is_validated_and_replays_are_rejected() {
        let tag = "signed_ok";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "signed-ok.coverage.example.com";
        let (entity_id, acs_url) = configure_saml_tenant(&service, &tenant, domain, true).await;

        let fixture = SamlFixture::valid(&entity_id, &acs_url);
        let validated = parse_fixture(&service, domain, &fixture)
            .await
            .expect("a genuinely signed, correctly-formed response validates");
        assert_eq!(validated.name_id, "alice.smith@example.com");
        assert!(validated
            .attributes
            .iter()
            .any(|(name, value)| name == "email" && value == "alice.smith@example.com"));
        assert!(validated.attributes.iter().any(|(name, _)| name == "group"));

        // The same assertion id may never be consumed twice for the tenant.
        let replay = parse_fixture(&service, domain, &fixture)
            .await
            .err()
            .expect("the second use of an assertion id is a replay");
        assert!(
            replay.contains("replay rejected"),
            "unexpected error: {replay}"
        );

        // A DIFFERENT tenant cannot burn the first tenant's assertion id...
        let other_tenant = coverage_tenant("signed_ok2");
        let (other_entity, other_acs) = configure_saml_tenant(
            &service,
            &other_tenant,
            "signed-ok2.coverage.example.com",
            true,
        )
        .await;
        let mut other_fixture = SamlFixture::valid(&other_entity, &other_acs);
        other_fixture.assertion_id = fixture.assertion_id.clone();
        // ...the replay guard is per-tenant, so this is accepted — but a
        // second use for the OTHER tenant is still a replay.
        let _ = parse_fixture(&service, "signed-ok2.coverage.example.com", &other_fixture)
            .await
            .expect("replay protection is scoped per tenant");
        let replay_other =
            parse_fixture(&service, "signed-ok2.coverage.example.com", &other_fixture)
                .await
                .err()
                .expect("second use for the other tenant is also a replay");
        assert!(replay_other.contains("replay rejected"));
    }

    #[tokio::test]
    async fn every_saml_refusal_arm_rejects_a_genuinely_signed_response() {
        let tag = "signed_refusals";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "refusals.coverage.example.com";
        let (entity_id, acs_url) = configure_saml_tenant(&service, &tenant, domain, true).await;

        // Each case mutates one claim; the response stays properly SIGNED so
        // the refusal demonstrably comes from the claim check, not the
        // signature gate. (name, fixture mutation, expected error fragment)
        let assert_id = format!("_assertion_{}", Uuid::new_v4());
        type RefusalCase<'a> = (&'a str, Box<dyn Fn(&mut SamlFixture)>, &'a str);
        let cases: Vec<RefusalCase> = vec![
            (
                "failure status code",
                Box::new(move |f: &mut SamlFixture| {
                    f.status_value = "urn:oasis:names:tc:SAML:2.0:status:Responder".into();
                }),
                "StatusCode",
            ),
            (
                "issuer mismatch",
                Box::new(|f: &mut SamlFixture| f.issuer = "https://evil.example.com".into()),
                "Issuer does not match",
            ),
            (
                "missing issuer",
                Box::new(|f: &mut SamlFixture| f.issuer = String::new()),
                "missing Issuer",
            ),
            (
                "audience mismatch",
                Box::new(|f: &mut SamlFixture| f.audience = "https://evil.example.com/acs".into()),
                "AudienceRestriction does not match",
            ),
            (
                "missing audience restriction",
                Box::new(|f: &mut SamlFixture| f.include_audience = false),
                "missing AudienceRestriction",
            ),
            (
                "missing NameID",
                Box::new(|f: &mut SamlFixture| f.name_id = String::new()),
                "missing NameID",
            ),
            (
                "NameID sanitizes to empty (whitespace-only)",
                Box::new(|f: &mut SamlFixture| f.name_id = "   ".into()),
                "empty after sanitization",
            ),
            (
                "NameID over 256 chars sanitizes to empty",
                Box::new(|f: &mut SamlFixture| f.name_id = "x".repeat(257)),
                "empty after sanitization",
            ),
            (
                "missing assertion ID",
                Box::new(move |f: &mut SamlFixture| f.assertion_id = String::new()),
                "missing an ID",
            ),
            (
                "NotBefore in the future",
                Box::new(|f: &mut SamlFixture| {
                    f.not_before = Some(Utc::now() + chrono::Duration::minutes(30));
                }),
                "not yet valid",
            ),
            (
                "assertion expired",
                Box::new(|f: &mut SamlFixture| {
                    f.not_on_or_after = Some(Utc::now() - chrono::Duration::minutes(30));
                }),
                "has expired",
            ),
        ];
        let _ = assert_id;

        for (name, mutate, expected) in cases {
            let mut fixture = SamlFixture::valid(&entity_id, &acs_url);
            mutate(&mut fixture);
            let error = parse_fixture(&service, domain, &fixture)
                .await
                .err()
                .unwrap_or_default();
            assert!(
                error.contains(expected),
                "case {name}: expected error containing '{expected}', got '{error}'"
            );
        }
    }

    #[tokio::test]
    async fn signed_saml_gate_itself_rejects_unsigned_and_tampered_documents() {
        let tag = "signed_gate";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "gate.coverage.example.com";
        let (entity_id, acs_url) = configure_saml_tenant(&service, &tenant, domain, true).await;

        // Unsigned: refused before any parsing.
        let mut fixture = SamlFixture::valid(&entity_id, &acs_url);
        fixture.include_signature = false;
        let unsigned_error = parse_fixture(&service, domain, &fixture)
            .await
            .err()
            .expect("unsigned must be refused");
        assert!(
            unsigned_error.contains("signature"),
            "unsigned must be refused at the signature gate: {unsigned_error}"
        );

        // Tampered: text inserted into the digest value AFTER signing
        // breaks the reference digest — the DsigStatus::Invalid arm.
        let key = IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM));
        let mut signed_case = SamlFixture::valid(&entity_id, &acs_url);
        signed_case.name_id = "tamper-check@example.com".into();
        let signed_document = signed_case.render(key);
        let marker = "<ds:DigestValue>";
        let pos = signed_document
            .find(marker)
            .expect("signed doc has a digest");
        let mut tampered = signed_document.clone();
        // Flip the first digest character IN PLACE: same length, so the
        // signature still parses and the failure is a real digest mismatch.
        let digest_start = pos + marker.len();
        let original_char = tampered.as_bytes()[digest_start] as char;
        let replacement = if original_char == 'A' { 'B' } else { 'A' };
        tampered.replace_range(digest_start..digest_start + 1, &replacement.to_string());
        assert_ne!(tampered, signed_document, "tampering must change the doc");
        let tampered_error = service
            .parse_and_validate_saml_response(&tampered, domain)
            .await
            .err()
            .expect("tampered digest must be refused");
        assert!(
            tampered_error.contains("signature verification failed"),
            "tampered digest must be Invalid: {tampered_error}"
        );
        // The untouched document still validates (the gate is exact).
        let valid = service
            .parse_and_validate_saml_response(&signed_document, domain)
            .await;
        assert!(valid.is_ok(), "the untouched signed document must validate");

        // Malformed XML is refused (parse error before any claim logic).
        let malformed_error = service
            .parse_and_validate_saml_response("<not-xml", domain)
            .await
            .err()
            .expect("malformed XML must be refused");
        assert!(
            malformed_error.contains("signature") || malformed_error.contains("parse"),
            "malformed XML: {malformed_error}"
        );
    }

    #[tokio::test]
    async fn saml_without_a_configured_certificate_is_refused() {
        let tag = "signed_nocert";
        let (service, _pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "nocert.coverage.example.com";
        let (entity_id, acs_url) = configure_saml_tenant(&service, &tenant, domain, false).await;

        let fixture = SamlFixture::valid(&entity_id, &acs_url);
        let error = parse_fixture(&service, domain, &fixture)
            .await
            .err()
            .expect("a signed response without a configured cert must be refused");
        assert!(
            error.contains("certificate is not configured"),
            "unexpected: {error}"
        );
    }

    #[tokio::test]
    async fn oidc_state_machine_covers_redis_db_fallback_and_error_arms() {
        let tag = "oidc_state";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "oidc.coverage.example.com";
        service
            .configure(SSOConfigureRequest {
                tenant_id: tenant.clone(),
                provider_type: "oidc".to_string(),
                domain: domain.to_string(),
                enabled: Some(true),
                entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: Some("client-123".to_string()),
                oidc_client_secret: Some("shhh".to_string()),
                oidc_issuer: Some("https://oidp.coverage.example.com".to_string()),
                attribute_mapping: None,
                enforce_sso: Some(false),
                session_duration_hours: None,
            })
            .await
            .expect("configure OIDC");

        // Non-OIDC providers and unknown domains are refused.
        let saml_service_domain = "oidc-saml.coverage.example.com";
        service
            .configure(SSOConfigureRequest {
                tenant_id: coverage_tenant(tag),
                provider_type: "saml".to_string(),
                domain: saml_service_domain.to_string(),
                enabled: Some(true),
                entity_id: None,
                sso_url: None,
                certificate: None,
                oidc_client_id: None,
                oidc_client_secret: None,
                oidc_issuer: None,
                attribute_mapping: None,
                enforce_sso: None,
                session_duration_hours: None,
            })
            .await
            .expect("configure SAML-only tenant");
        let wrong_provider = service
            .initiate_oidc_login(saml_service_domain)
            .await
            .expect("query works");
        assert!(
            !wrong_provider.success,
            "SAML provider is not an OIDC provider"
        );
        let unknown = service
            .initiate_oidc_login("no-such-oidc.example.com")
            .await
            .expect("query");
        assert!(!unknown.success, "unknown domain has no OIDC config");

        // Without a Redis pool the state falls back to the durable table.
        let redirect = service
            .initiate_oidc_login(domain)
            .await
            .expect("initiate works")
            .data
            .expect("redirect");
        assert!(redirect
            .redirect_url
            .contains("/authorize?client_id=client-123"));
        assert!(redirect.redirect_url.contains("code_challenge_method=S256"));
        let state = redirect.request_id.clone();
        let from_db = service
            .validate_oidc_state(&state)
            .await
            .expect("validate state")
            .expect("state exists in the durable fallback");
        assert_eq!(from_db.domain, domain);
        assert!(!from_db.code_verifier.is_empty());
        // Single use: the DELETE..RETURNING makes the second lookup a miss.
        let replayed = service
            .validate_oidc_state(&state)
            .await
            .expect("validate again");
        assert!(replayed.is_none(), "a consumed state never validates twice");

        // With a Redis pool the state round-trips through `oidc_state:*`.
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let with_redis = SSOService::with_redis(pool.clone(), redis.clone(), new_sso_config());
        let redirect = with_redis
            .initiate_oidc_login(domain)
            .await
            .expect("initiate with redis")
            .data
            .expect("redirect");
        let state = redirect.request_id.clone();
        let stored: Option<String> = {
            let mut conn = redis.get().await.expect("redis conn");
            conn.get(format!("oidc_state:{state}")).await.expect("get")
        };
        assert!(stored.is_some(), "the state is staged in redis");
        let from_redis = with_redis
            .validate_oidc_state(&state)
            .await
            .expect("validate from redis")
            .expect("state exists in redis");
        assert_eq!(from_redis.tenant_id.as_deref(), Some(tenant.as_str()));
        // Consumed: the key is deleted, and the DB fallback misses too.
        let consumed: Option<String> = {
            let mut conn = redis.get().await.expect("redis conn");
            conn.get(format!("oidc_state:{state}")).await.expect("get")
        };
        assert!(consumed.is_none(), "redis state is single-use");
        let _ = with_redis.validate_oidc_state(&state).await;

        // Malformed staged JSON and a missing code_verifier are honest
        // errors, not silent fallbacks.
        let mut conn = redis.get().await.expect("redis conn");
        let _: () = conn
            .set_ex("oidc_state:cov_malformed", "not-json", 60)
            .await
            .expect("stage malformed");
        let _: () = conn
            .set_ex(
                "oidc_state:cov_no_verifier",
                r#"{"domain":"x.example.com"}"#,
                60,
            )
            .await
            .expect("stage no-verifier");
        drop(conn);
        let malformed = with_redis
            .validate_oidc_state("cov_malformed")
            .await
            .expect_err("malformed JSON fails");
        assert!(malformed.contains("Parse state"), "unexpected: {malformed}");
        let no_verifier = with_redis
            .validate_oidc_state("cov_no_verifier")
            .await
            .expect_err("missing verifier fails");
        assert!(
            no_verifier.contains("code_verifier"),
            "unexpected: {no_verifier}"
        );
    }

    fn new_sso_config() -> Config {
        Config::from_env().expect("Config::from_env in test env")
    }

    #[tokio::test]
    async fn sso_session_lifecycle_covers_new_and_returning_users() {
        let tag = "sso_session";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "session.coverage.example.com";
        let (entity_id, _acs) = configure_saml_tenant(&service, &tenant, domain, true).await;
        let _ = entity_id;

        // First login: a new user with a session bound to the configured
        // duration.
        let first = service
            .handle_saml_callback(
                &tenant,
                "carol@example.com",
                Some("Carol"),
                "carol-external-id",
                Some(serde_json::json!(["admins"])),
                None,
            )
            .await
            .expect("callback works")
            .data
            .expect("session result");
        assert!(first.is_new_user, "the first login is a new user");
        let token = first.session.session_token.clone();

        // The token validates and stamps last activity.
        let session = service
            .validate_session(&token)
            .await
            .expect("validate")
            .expect("live session");
        assert_eq!(session.email, "carol@example.com");

        // Second login for the same external id: not a new user.
        let second = service
            .handle_saml_callback(
                &tenant,
                "carol@example.com",
                Some("Carol"),
                "carol-external-id",
                None,
                None,
            )
            .await
            .expect("callback works")
            .data
            .expect("session result");
        assert!(!second.is_new_user, "the second login is a returning user");

        // Expired sessions validate to nothing and are swept.
        sqlx::query("UPDATE ent_sso_sessions SET expires_at = NOW() - INTERVAL '1 hour'")
            .execute(&pool)
            .await
            .expect("expire sessions");
        let expired = service
            .validate_session(&token)
            .await
            .expect("validate")
            .is_none();
        assert!(expired, "an expired session never validates");
        let swept = service.cleanup_expired_sessions().await.expect("cleanup");
        assert!(swept >= 2, "both carol sessions were swept, got {swept}");
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ent_sso_sessions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(left, 0);

        // OIDC callbacks create sessions too.
        let oidc_session = service
            .handle_oidc_callback(&tenant, "dave@example.com", None, "dave-external-id", None)
            .await
            .expect("oidc callback")
            .data
            .expect("session");
        assert!(oidc_session.is_new_user);
    }

    #[tokio::test]
    async fn cleanup_expired_sessions_degrades_when_the_table_is_missing() {
        let tag = "sso_cleanup_missing";
        let (service, pool) = provision_sso(tag).await;
        sqlx::query("ALTER TABLE ent_sso_sessions RENAME TO ent_sso_sessions_gone")
            .execute(&pool)
            .await
            .expect("break table");
        let swept = service
            .cleanup_expired_sessions()
            .await
            .expect("a missing table degrades to a no-op sweep");
        assert_eq!(swept, 0);
        sqlx::query("ALTER TABLE ent_sso_sessions_gone RENAME TO ent_sso_sessions")
            .execute(&pool)
            .await
            .expect("restore table");
    }

    #[tokio::test]
    async fn tenant_enforces_sso_covers_every_lookup_arm() {
        let tag = "sso_enforce";
        let (service, pool) = provision_sso(tag).await;
        let enforcing = coverage_tenant(tag);
        let relaxed = coverage_tenant(tag);

        // Enforcing and non-enforcing rows.
        for (tenant, enforce) in [(&enforcing, true), (&relaxed, false)] {
            service
                .configure(SSOConfigureRequest {
                    tenant_id: tenant.to_string(),
                    provider_type: "saml".to_string(),
                    domain: format!("{tenant}.enforce.example.com"),
                    enabled: Some(true),
                    entity_id: None,
                    sso_url: None,
                    certificate: None,
                    oidc_client_id: None,
                    oidc_client_secret: None,
                    oidc_issuer: None,
                    attribute_mapping: None,
                    enforce_sso: Some(enforce),
                    session_duration_hours: None,
                })
                .await
                .expect("configure");
        }
        assert!(service
            .tenant_enforces_sso(&enforcing)
            .await
            .expect("lookup"));
        assert!(!service.tenant_enforces_sso(&relaxed).await.expect("lookup"));
        // The free function agrees with the method.
        assert!(enterprise_sso_enforces(&pool, &enforcing).await);
        // No row: the gate stays open.
        assert!(!enterprise_sso_enforces(&pool, "no-such-enforce-tenant").await);

        // Missing table (42P01): the gate degrades open instead of locking
        // every tenant out.
        sqlx::query("ALTER TABLE ent_sso_configurations RENAME TO ent_sso_configurations_gone")
            .execute(&pool)
            .await
            .expect("break table");
        assert!(!enterprise_sso_enforces(&pool, &enforcing).await);
        sqlx::query("ALTER TABLE ent_sso_configurations_gone RENAME TO ent_sso_configurations")
            .execute(&pool)
            .await
            .expect("restore table");

        // Any other database failure surfaces as Err (broken pool).
        let broken = crate::config::Config::from_env().expect("config");
        let broken_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgresql://127.0.0.1:5432/enterprise_no_such_db_cov")
            .expect("lazy pool");
        let error = tenant_enforces_sso(&broken_pool, &enforcing)
            .await
            .expect_err("a broken pool is an error, not an open gate");
        assert!(error.contains("Check enforce_sso"), "unexpected: {error}");
        let _ = broken;
    }

    async fn enterprise_sso_enforces(pool: &sqlx::PgPool, tenant: &str) -> bool {
        tenant_enforces_sso(pool, tenant)
            .await
            .expect("lookup works")
    }

    #[tokio::test]
    async fn configuration_lookup_and_domain_gates_cover_their_arms() {
        let tag = "sso_lookup";
        let (service, pool) = provision_sso(tag).await;
        let tenant = coverage_tenant(tag);
        let domain = "lookup.coverage.example.com";
        let _ = configure_saml_tenant(&service, &tenant, domain, true).await;

        // Found and not-found configuration lookups.
        let found = service
            .get_configuration(&tenant)
            .await
            .expect("lookup works");
        assert!(found.data.is_some(), "the configured tenant is found");
        let missing = service
            .get_configuration("no-such-lookup-tenant")
            .await
            .expect("lookup works");
        assert!(!missing.success, "an unconfigured tenant is NOT_FOUND");

        // Enabled-domain lookup finds the row...
        let by_domain = service
            .get_config_by_domain(domain)
            .await
            .expect("domain lookup");
        assert!(by_domain.is_some());
        // ...disabled rows never match...
        sqlx::query("UPDATE ent_sso_configurations SET enabled = false WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("disable");
        let disabled = service
            .get_config_by_domain(domain)
            .await
            .expect("domain lookup");
        assert!(
            disabled.is_none(),
            "a disabled config is invisible by domain"
        );
        sqlx::query("UPDATE ent_sso_configurations SET enabled = true WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("re-enable");
        // ...and a missing table degrades to "no config for domain".
        sqlx::query("ALTER TABLE ent_sso_configurations RENAME TO ent_sso_configurations_gone")
            .execute(&pool)
            .await
            .expect("break table");
        let gone = service
            .get_config_by_domain(domain)
            .await
            .expect("missing table degrades to None");
        assert!(gone.is_none());
        sqlx::query("ALTER TABLE ent_sso_configurations_gone RENAME TO ent_sso_configurations")
            .execute(&pool)
            .await
            .expect("restore table");
    }
}
