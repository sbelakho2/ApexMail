//! Email Preference Centre — self-service consent and unsubscribe via encrypted tokens.
//!
//! Endpoints:
//!   POST /preferences/opt-out/{token}    — unsubscribe (consent withdrawal + suppression)
//!   GET  /preferences/status/{token}     — current consent status
//!   POST /preferences/update/{token}     — update consent preferences
//!   GET  /preferences/center/{tenant_id} — admin health overview
//!
//! Token format (compatible with tracking-service codec):
//!   base64url( IV[12] || AuthTag[16] || AES-128-GCM( tenantId:recipient:unix_ms ) )

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes128Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use base64::Engine;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::routes::{err_json, ok_json, verify_bearer, AppState};
use crate::types::{AuditAction, AuditOutcome, AuditResource, ConsentSource, ConsentType, LogContext};

type HmacSha256 = Hmac<Sha256>;

const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

#[derive(Zeroize, ZeroizeOnDrop)]
struct EncKey([u8; 16]);

#[derive(Zeroize, ZeroizeOnDrop)]
struct SigKey([u8; 32]);

fn derive_key_hmac(secret: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize derive_key_hmac HMAC");
            return Zeroizing::new(Vec::new());
        }
    };
    mac.update(info);
    let result = mac.finalize().into_bytes();
    Zeroizing::new(result[..len].to_vec())
}

pub struct PreferenceCodec {
    enc_key: EncKey,
    _sig_key: SigKey,
}

impl PreferenceCodec {
    pub fn new(master_secret: &str) -> Self {
        let enc_key = derive_key_hmac(master_secret.as_bytes(), b"encryption", 16);
        let sig_key = derive_key_hmac(master_secret.as_bytes(), b"signature", 32);
        let mut ek = [0u8; 16];
        ek.copy_from_slice(&enc_key[..16]);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&sig_key[..32]);
        Self {
            enc_key: EncKey(ek),
            _sig_key: SigKey(sk),
        }
    }

    pub fn generate_token(&self, tenant_id: &str, recipient: &str) -> Result<String, String> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let payload = format!("{}:{}:{}", tenant_id, recipient, ts_ms);
        let (iv, tag, ct) = self
            .aes128gcm_encrypt(payload.as_bytes())
            .map_err(|e| format!("encrypt: {e}"))?;
        let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ct.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ct);
        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }

    pub fn decode_token(&self, token: &str) -> Option<PreferenceTokenData> {
        if token.len() < 10 || token.len() > 4096 {
            return None;
        }
        let combined = URL_SAFE_NO_PAD.decode(token).ok()?;
        if combined.len() < IV_LEN + AUTH_TAG_LEN + 1 {
            return None;
        }
        let (iv_bytes, rest) = combined.split_at(IV_LEN);
        let (tag_bytes, ciphertext) = rest.split_at(AUTH_TAG_LEN);
        let plain = self
            .aes128gcm_decrypt(ciphertext, iv_bytes, tag_bytes)
            .ok()?;
        let payload = String::from_utf8(plain).ok()?;
        parse_token_payload(&payload)
    }

    fn aes128gcm_encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<([u8; IV_LEN], [u8; AUTH_TAG_LEN], Vec<u8>), String> {
        let mut iv_bytes = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv_bytes);
        let key = Key::<Aes128Gcm>::from_slice(&self.enc_key.0);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(&iv_bytes);
        let mut ct_with_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("AES encrypt: {e}"))?;
        let tag_start = ct_with_tag.len() - AUTH_TAG_LEN;
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&ct_with_tag[tag_start..]);
        ct_with_tag.truncate(tag_start);
        Ok((iv_bytes, tag, ct_with_tag))
    }

    fn aes128gcm_decrypt(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key = Key::<Aes128Gcm>::from_slice(&self.enc_key.0);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(iv);
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);
        cipher
            .decrypt(nonce, ct_with_tag.as_slice())
            .map_err(|e| format!("AES decrypt: {e}"))
    }
}

#[derive(Debug, Clone)]
pub struct PreferenceTokenData {
    pub tenant_id: String,
    pub email: String,
    pub timestamp_ms: u64,
}

fn parse_token_payload(payload: &str) -> Option<PreferenceTokenData> {
    let last_colon = payload.rfind(':')?;
    let ts_str = &payload[last_colon + 1..];
    if ts_str.is_empty() || !ts_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let prefix = &payload[..last_colon];
    let first_colon = prefix.find(':')?;
    let tenant_id = prefix[..first_colon].to_owned();
    let email = prefix[first_colon + 1..].to_owned();
    if tenant_id.is_empty() || email.is_empty() {
        return None;
    }
    let timestamp_ms: u64 = ts_str.parse().ok()?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let max_ms = 30u64 * 24 * 60 * 60 * 1000;
    if now_ms.saturating_sub(timestamp_ms) > max_ms {
        return None;
    }
    Some(PreferenceTokenData {
        tenant_id,
        email,
        timestamp_ms,
    })
}

#[derive(Debug, Deserialize)]
pub struct PreferencesUpdateBody {
    pub consents: PreferencesConsents,
}

#[derive(Debug, Deserialize)]
pub struct PreferencesConsents {
    pub marketing: Option<bool>,
    pub analytics: Option<bool>,
    pub profiling: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConsentEntry {
    pub consent_type: String,
    pub granted: bool,
    pub granted_at: Option<String>,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
    pub source: String,
}

#[derive(sqlx::FromRow)]
struct ConsentStatusRow {
    consent_type: String,
    granted: bool,
    granted_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    expires_at: Option<chrono::DateTime<Utc>>,
    source: String,
}

// ── Router builder ────────────────────────────────────────────────────────

pub fn create_preference_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/preferences/opt-out/{token}",
            post(handle_opt_out),
        )
        .route(
            "/preferences/status/{token}",
            get(handle_consent_status),
        )
        .route(
            "/preferences/update/{token}",
            post(handle_preferences_update),
        )
        .route(
            "/preferences/center/{tenant_id}",
            get(handle_preference_center_health),
        )
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────

async fn handle_opt_out(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let codec = &state.preference_codec;
    let data = match codec.decode_token(&token) {
        Some(d) => d,
        None => return err_json(StatusCode::BAD_REQUEST, "Invalid or expired token"),
    };

    let subscriber_id = format!("sub-{}", Uuid::new_v4());

    if let Err(e) = state
        .gdpr
        .record_consent(
            &data.tenant_id,
            &subscriber_id,
            &data.email,
            ConsentType::Marketing,
            false,
            ConsentSource::PreferenceCenter,
            None,
        )
        .await
    {
        error!(error = %e, email = %data.email, "Opt-out consent recording failed");
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "Failed to process opt-out");
    }

    let _ = sqlx::query(
        "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
         VALUES ($1, $2, $3, 'preference_center', NOW())
         ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'preference_center'",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&data.tenant_id)
    .bind(&data.email)
    .execute(&state.db)
    .await;

    let _ = state
        .audit_logger
        .log(
            AuditAction::Update,
            AuditResource::Consent,
            Some(&data.tenant_id),
            serde_json::json!({
                "email": data.email,
                "action": "opt_out",
                "source": "preference_center",
                "cascade": ["analytics", "profiling"],
            }),
            AuditOutcome::Success,
            None,
            &LogContext {
                tenant_id: Some(data.tenant_id.clone()),
                user_id: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            },
        )
        .await;

    info!(email = %data.email, tenant_id = %data.tenant_id, "Preference center opt-out");
    ok_json(serde_json::json!({
        "status": "unsubscribed",
        "email": data.email,
        "message": "You have been unsubscribed from all marketing communications.",
    }))
}

async fn handle_consent_status(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    let data = match state.preference_codec.decode_token(&token) {
        Some(d) => d,
        None => return err_json(StatusCode::BAD_REQUEST, "Invalid or expired token"),
    };

    let rows: Result<Vec<ConsentStatusRow>, _> = sqlx::query_as(
        "SELECT consent_type, granted, granted_at, revoked_at, expires_at, source
         FROM consent_records
         WHERE tenant_id = $1 AND email = $2
         ORDER BY consent_type",
    )
    .bind(&data.tenant_id)
    .bind(&data.email)
    .fetch_all(&state.db)
    .await;

    let entries: Vec<ConsentEntry> = match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|r| ConsentEntry {
                consent_type: r.consent_type,
                granted: r.granted,
                granted_at: r.granted_at.map(|t| t.to_rfc3339()),
                revoked_at: r.revoked_at.map(|t| t.to_rfc3339()),
                expires_at: r.expires_at.map(|t| t.to_rfc3339()),
                source: r.source,
            })
            .collect(),
        Err(e) => {
            error!(error = %e, "Failed to fetch consent status");
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch consent status");
        }
    };

    ok_json(serde_json::json!({
        "email": data.email,
        "tenant_id": data.tenant_id,
        "consents": entries,
    }))
}

async fn handle_preferences_update(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    Json(body): Json<PreferencesUpdateBody>,
) -> impl IntoResponse {
    let data = match state.preference_codec.decode_token(&token) {
        Some(d) => d,
        None => return err_json(StatusCode::BAD_REQUEST, "Invalid or expired token"),
    };

    let subscriber_id = format!("sub-{}", Uuid::new_v4());
    let mut results = Vec::new();

    let consent_types = [
        ("marketing", body.consents.marketing, ConsentType::Marketing),
        ("analytics", body.consents.analytics, ConsentType::Analytics),
        ("profiling", body.consents.profiling, ConsentType::Profiling),
    ];

    for (name, opt, ct) in consent_types {
        if let Some(granted) = opt {
            match state
                .gdpr
                .record_consent(
                    &data.tenant_id,
                    &subscriber_id,
                    &data.email,
                    ct,
                    granted,
                    ConsentSource::PreferenceCenter,
                    None,
                )
                .await
            {
                Ok(record) => {
                    results.push(serde_json::json!({
                        "consent_type": name,
                        "granted": granted,
                        "id": record.id,
                    }));
                }
                Err(e) => {
                    error!(error = %e, consent_type = name, "Preference update failed");
                    return err_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("Failed to update {} consent", name),
                    );
                }
            }

            if !granted && ct == ConsentType::Marketing {
                let _ = sqlx::query(
                    "INSERT INTO suppression_list (id, tenant_id, email, reason, created_at)
                     VALUES ($1, $2, $3, 'preference_center', NOW())
                     ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'preference_center'",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(&data.tenant_id)
                .bind(&data.email)
                .execute(&state.db)
                .await;
            }
        }
    }

    let _ = state
        .audit_logger
        .log(
            AuditAction::Update,
            AuditResource::Consent,
            Some(&data.tenant_id),
            serde_json::json!({
                "email": data.email,
                "action": "preferences_update",
                "source": "preference_center",
                "changes": &results,
            }),
            AuditOutcome::Success,
            None,
            &LogContext {
                tenant_id: Some(data.tenant_id.clone()),
                user_id: None,
                session_id: None,
                ip_address: None,
                user_agent: None,
            },
        )
        .await;

    info!(email = %data.email, tenant_id = %data.tenant_id, "Preference center update");
    ok_json(serde_json::json!({
        "status": "updated",
        "email": data.email,
        "changes": results,
    }))
}

async fn handle_preference_center_health(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;

    let total: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM consent_records WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));

    let active: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM consent_records WHERE tenant_id = $1 AND granted = true",
    )
    .bind(&tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let opt_out_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM suppression_list WHERE tenant_id = $1 AND reason = 'preference_center'",
    )
    .bind(&tenant_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let opt_out_rate = if total.0 > 0 {
        (opt_out_count.0 as f64 / total.0 as f64) * 100.0
    } else {
        0.0
    };

    Ok(ok_json(serde_json::json!({
        "tenant_id": tenant_id,
        "total_consents": total.0,
        "active_consents": active.0,
        "opt_out_rate": opt_out_rate,
        "calculated_at": Utc::now().to_rfc3339(),
    })))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_codec() -> PreferenceCodec {
        PreferenceCodec::new("test-pref-secret-minimum-32-bytes!!")
    }

    #[test]
    fn token_roundtrip() {
        let codec = test_codec();
        let token = codec
            .generate_token("tenant_1", "user@example.com")
            .expect("generate");
        let data = codec.decode_token(&token).expect("decode");
        assert_eq!(data.tenant_id, "tenant_1");
        assert_eq!(data.email, "user@example.com");
    }

    #[test]
    fn invalid_token_rejected() {
        let codec = test_codec();
        assert!(codec.decode_token("not-a-valid-token").is_none());
        assert!(codec.decode_token("").is_none());
    }

    #[test]
    fn different_codec_rejects() {
        let c1 = PreferenceCodec::new("secret-one-aaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let c2 = PreferenceCodec::new("secret-two-aaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let token = c1.generate_token("t", "e@x.com").expect("gen");
        assert!(c2.decode_token(&token).is_none());
    }

    #[test]
    fn tampered_token_rejected() {
        let codec = test_codec();
        let token = codec.generate_token("t", "r@x.com").expect("gen");
        let mut bytes = token.as_bytes().to_vec();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let tampered = String::from_utf8(bytes).expect("utf8");
        assert!(codec.decode_token(&tampered).is_none());
    }

    #[test]
    fn token_with_colons_roundtrip() {
        let codec = test_codec();
        let token = codec
            .generate_token("tenant-id-123", "complex+tag@host.example.com")
            .expect("gen");
        let data = codec.decode_token(&token).expect("decode");
        assert_eq!(data.tenant_id, "tenant-id-123");
        assert_eq!(data.email, "complex+tag@host.example.com");
    }
}
