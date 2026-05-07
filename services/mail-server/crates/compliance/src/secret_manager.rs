//! Secret management — AES-256-GCM encrypted secret storage with access control,
//! version history, auto-rotation, and type-specific secret generation.
//!
//! Encryption:AES-256-GCM with a 32-byte key derived via SHA-256 of the master
//! key + salt. 12-byte random nonce per encryption. Storage format:base64 of
//! `nonce (12) || ciphertext || tag (16)`.
//!
//! Access control:3-level hierarchy (read=1, write=2, admin=3). Creator always
//! has admin. Grants have optional expiry and revocation.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::SecretsConfig;
use crate::types::*;

pub struct SecretManager {
    db: PgPool,
    config: SecretsConfig,
    /// 32-byte derived encryption key
    cipher_key: [u8; 32],
}

impl SecretManager {
    pub fn new(db: PgPool, config: SecretsConfig) -> Result<Self, String> {
        let cipher_key = derive_key(&config.encryption_key)?;
        Ok(Self {
            db,
            config,
            cipher_key,
        })
    }

    // ── CRUD ────────────────────────────────────────────────

    /// Create a new secret. If `value` is None, auto-generates based on type.
    pub async fn create_secret(&self, input: &SecretCreateInput) -> Result<Secret, String> {
        let value = match &input.value {
            Some(v) => v.clone(),
            None => generate_secret_value(input.secret_type),
        };

        let encrypted = self.encrypt(&value)?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let next_rotation = input
            .rotation_schedule
            .as_ref()
            .map(|rs| now + Duration::days(rs.interval_days));

        let rotation_json = input
            .rotation_schedule
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| format!("failed to serialize rotation schedule: {e}"))?;

        sqlx::query(
            "INSERT INTO secrets
               (id, tenant_id, name, type, encrypted_value, version,
                rotation_schedule, last_rotated_at, next_rotation_at,
                created_by, created_at, updated_at, expires_at)
             VALUES ($1,$2,$3,$4,$5,1,$6,NULL,$7,$8,$9,$9,$10)",
        )
        .bind(&id)
        .bind(&input.tenant_id)
        .bind(&input.name)
        .bind(input.secret_type.to_string())
        .bind(&encrypted)
        .bind(&rotation_json)
        .bind(next_rotation)
        .bind(&input.created_by)
        .bind(now)
        .bind(input.expires_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        // Grant creator admin access
        self.grant_access_internal(
            &id,
            &input.created_by,
            AccessLevel::Admin,
            &input.created_by,
            None,
        )
        .await?;

        // Save initial version
        self.save_version(&id, 1, &encrypted).await?;

        let secret = Secret {
            id,
            tenant_id: input.tenant_id.clone(),
            name: input.name.clone(),
            secret_type: input.secret_type,
            encrypted_value: encrypted,
            version: 1,
            rotation_schedule: input.rotation_schedule.clone(),
            last_rotated_at: None,
            next_rotation_at: next_rotation,
            created_by: input.created_by.clone(),
            created_at: now,
            updated_at: now,
            expires_at: input.expires_at,
        };

        info!(secret_id = %secret.id, name = %secret.name, "Secret created");
        Ok(secret)
    }

    /// Get a secret (decrypted) if the user has read access.
    pub async fn get_secret(
        &self,
        secret_id: &str,
        user_id: &str,
    ) -> Result<Option<(Secret, String)>, String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Read)
            .await?
        {
            return Err("Access denied to secret".into());
        }

        let row = self.fetch_secret_row(secret_id).await?;
        match row {
            Some(s) => {
                // Check expiry
                if let Some(exp) = s.expires_at {
                    if exp < Utc::now() {
                        return Err("Secret has expired".into());
                    }
                }
                let decrypted = self.decrypt(&s.encrypted_value)?;
                self.log_access(secret_id, user_id, "read").await?;
                Ok(Some((s, decrypted)))
            }
            None => Ok(None),
        }
    }

    /// Get a secret by tenant + name.
    pub async fn get_secret_by_name(
        &self,
        tenant_id: &str,
        name: &str,
        user_id: &str,
    ) -> Result<Option<(Secret, String)>, String> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM secrets WHERE tenant_id = $1 AND name = $2")
                .bind(tenant_id)
                .bind(name)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;

        match row {
            Some((id,)) => self.get_secret(&id, user_id).await,
            None => Ok(None),
        }
    }

    /// Update secret metadata (not the value — use rotate for that).
    pub async fn update_secret(
        &self,
        secret_id: &str,
        user_id: &str,
        update: &SecretUpdateInput,
    ) -> Result<Secret, String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Write)
            .await?
        {
            return Err("Access denied to modify secret".into());
        }

        if let Some(name) = &update.name {
            sqlx::query("UPDATE secrets SET name = $1, updated_at = NOW() WHERE id = $2")
                .bind(name)
                .bind(secret_id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
        }

        if let Some(rs) = &update.rotation_schedule {
            let json = serde_json::to_value(rs).map_err(|e| format!("JSON: {e}"))?;
            let next = Utc::now() + Duration::days(rs.interval_days);
            sqlx::query(
                "UPDATE secrets SET rotation_schedule = $1, next_rotation_at = $2, updated_at = NOW()
                 WHERE id = $3",
            )
            .bind(&json)
            .bind(next)
            .bind(secret_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?;
        }

        if update.expires_at.is_some() {
            sqlx::query("UPDATE secrets SET expires_at = $1, updated_at = NOW() WHERE id = $2")
                .bind(update.expires_at)
                .bind(secret_id)
                .execute(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?;
        }

        self.log_access(secret_id, user_id, "update").await?;

        self.fetch_secret_row(secret_id)
            .await?
            .ok_or_else(|| "Secret not found".into())
    }

    /// Rotate a secret (generate or set new value).
    pub async fn rotate_secret(
        &self,
        secret_id: &str,
        user_id: &str,
        new_value: Option<&str>,
    ) -> Result<(Secret, String), String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Write)
            .await?
        {
            return Err("Access denied to modify secret".into());
        }

        let existing = self
            .fetch_secret_row(secret_id)
            .await?
            .ok_or("Secret not found")?;

        let value = match new_value {
            Some(v) => v.to_string(),
            None => generate_secret_value(existing.secret_type),
        };

        let encrypted = self.encrypt(&value)?;
        let new_version = existing.version + 1;
        let now = Utc::now();

        let next_rotation = existing
            .rotation_schedule
            .as_ref()
            .map(|rs| now + Duration::days(rs.interval_days));

        sqlx::query(
            "UPDATE secrets SET encrypted_value = $1, version = $2,
                    last_rotated_at = $3, next_rotation_at = $4, updated_at = $3
             WHERE id = $5",
        )
        .bind(&encrypted)
        .bind(new_version)
        .bind(now)
        .bind(next_rotation)
        .bind(secret_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.save_version(secret_id, new_version, &encrypted)
            .await?;
        self.prune_versions(secret_id).await?;
        self.log_access(secret_id, user_id, "rotate").await?;

        let updated = self
            .fetch_secret_row(secret_id)
            .await?
            .ok_or("Secret not found after rotation")?;

        info!(secret_id, version = new_version, "Secret rotated");
        Ok((updated, value))
    }

    /// Delete a secret (archive first).
    pub async fn delete_secret(&self, secret_id: &str, user_id: &str) -> Result<(), String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Admin)
            .await?
        {
            return Err("Access denied to delete secret".into());
        }

        // Archive
        sqlx::query("INSERT INTO secrets_archive SELECT * FROM secrets WHERE id = $1")
            .bind(secret_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        // Delete versions, access, then secret
        sqlx::query("DELETE FROM secret_versions WHERE secret_id = $1")
            .bind(secret_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        sqlx::query("DELETE FROM secret_access WHERE secret_id = $1")
            .bind(secret_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        sqlx::query("DELETE FROM secrets WHERE id = $1")
            .bind(secret_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        self.log_access(secret_id, user_id, "delete").await?;
        info!(secret_id, "Secret deleted");
        Ok(())
    }

    /// List secrets for a tenant (no decrypted values).
    pub async fn list_secrets(
        &self,
        tenant_id: &str,
        secret_type: Option<SecretType>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Secret>, String> {
        let rows: Vec<SecretRow> = if let Some(st) = secret_type {
            sqlx::query_as(
                "SELECT id, tenant_id, name, type, encrypted_value, version,
                        rotation_schedule, last_rotated_at, next_rotation_at,
                        created_by, created_at, updated_at, expires_at
                 FROM secrets WHERE tenant_id = $1 AND type = $2
                 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(tenant_id)
            .bind(st.to_string())
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?
        } else {
            sqlx::query_as(
                "SELECT id, tenant_id, name, type, encrypted_value, version,
                        rotation_schedule, last_rotated_at, next_rotation_at,
                        created_by, created_at, updated_at, expires_at
                 FROM secrets WHERE tenant_id = $1
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("DB error: {e}"))?
        };

        rows.into_iter().map(|r| r.into_secret()).collect()
    }

    // ── Access Control ──────────────────────────────────────

    pub async fn grant_access(
        &self,
        secret_id: &str,
        user_id: &str,
        access_type: AccessLevel,
        granted_by: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<SecretAccess, String> {
        if !self
            .check_access(secret_id, granted_by, AccessLevel::Admin)
            .await?
        {
            return Err("Access denied to grant secret access".into());
        }
        self.grant_access_internal(secret_id, user_id, access_type, granted_by, expires_at)
            .await
    }

    pub async fn revoke_access(
        &self,
        secret_id: &str,
        user_id: &str,
        revoked_by: &str,
    ) -> Result<(), String> {
        if !self
            .check_access(secret_id, revoked_by, AccessLevel::Admin)
            .await?
        {
            return Err("Access denied to revoke secret access".into());
        }

        sqlx::query(
            "UPDATE secret_access SET revoked_at = NOW()
             WHERE secret_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(secret_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(())
    }

    pub async fn check_access(
        &self,
        secret_id: &str,
        user_id: &str,
        required: AccessLevel,
    ) -> Result<bool, String> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT access_type FROM secret_access
             WHERE secret_id = $1 AND user_id = $2
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(secret_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        match row {
            Some((access_str,)) => {
                let level: AccessLevel = match access_str.as_str() {
                    "admin" => AccessLevel::Admin,
                    "write" => AccessLevel::Write,
                    _ => AccessLevel::Read,
                };
                Ok(level.level() >= required.level())
            }
            None => Ok(false),
        }
    }

    // ── Version History ─────────────────────────────────────

    pub async fn get_version_history(
        &self,
        secret_id: &str,
        user_id: &str,
    ) -> Result<Vec<(i32, chrono::DateTime<Utc>)>, String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Read)
            .await?
        {
            return Err("Access denied to secret history".into());
        }

        let rows: Vec<(i32, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT version, created_at FROM secret_versions
             WHERE secret_id = $1 ORDER BY version DESC",
        )
        .bind(secret_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(rows)
    }

    pub async fn rollback_to_version(
        &self,
        secret_id: &str,
        version: i32,
        user_id: &str,
    ) -> Result<Secret, String> {
        if !self
            .check_access(secret_id, user_id, AccessLevel::Admin)
            .await?
        {
            return Err("Access denied to rollback secret".into());
        }

        let row: Option<(String,)> = sqlx::query_as(
            "SELECT encrypted_value FROM secret_versions
             WHERE secret_id = $1 AND version = $2",
        )
        .bind(secret_id)
        .bind(version)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let (encrypted,) = row.ok_or("Version not found")?;

        sqlx::query(
            "UPDATE secrets SET encrypted_value = $1, version = $2, updated_at = NOW()
             WHERE id = $3",
        )
        .bind(&encrypted)
        .bind(version)
        .bind(secret_id)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        self.log_access(secret_id, user_id, "rollback").await?;

        self.fetch_secret_row(secret_id)
            .await?
            .ok_or_else(|| "Secret not found after rollback".into())
    }

    // ── Auto-Rotation ───────────────────────────────────────

    /// Get secrets due for rotation.
    pub async fn get_secrets_for_rotation(&self) -> Result<Vec<Secret>, String> {
        let rows: Vec<SecretRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, type, encrypted_value, version,
                    rotation_schedule, last_rotated_at, next_rotation_at,
                    created_by, created_at, updated_at, expires_at
             FROM secrets
             WHERE next_rotation_at IS NOT NULL AND next_rotation_at <= NOW()
               AND rotation_schedule IS NOT NULL",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        rows.into_iter().map(|r| r.into_secret()).collect()
    }

    /// Process all auto-rotations.
    pub async fn process_auto_rotations(&self) -> Result<AutoRotationResult, String> {
        let due = self.get_secrets_for_rotation().await?;
        let mut rotated = Vec::new();
        let mut errors = Vec::new();

        for secret in &due {
            if let Some(rs) = &secret.rotation_schedule {
                if rs.auto_rotate {
                    match self
                        .rotate_secret(&secret.id, &secret.created_by, None)
                        .await
                    {
                        Ok(_) => rotated.push(secret.id.clone()),
                        Err(e) => errors.push((secret.id.clone(), e)),
                    }
                }
            }
        }

        Ok(AutoRotationResult { rotated, errors })
    }

    // ── Internal Helpers ────────────────────────────────────

    async fn grant_access_internal(
        &self,
        secret_id: &str,
        user_id: &str,
        access_type: AccessLevel,
        granted_by: &str,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<SecretAccess, String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO secret_access
               (id, secret_id, user_id, access_type, granted_by, granted_at, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (secret_id, user_id) DO UPDATE SET
               access_type = EXCLUDED.access_type,
               granted_by = EXCLUDED.granted_by,
               granted_at = EXCLUDED.granted_at,
               expires_at = EXCLUDED.expires_at,
               revoked_at = NULL",
        )
        .bind(&id)
        .bind(secret_id)
        .bind(user_id)
        .bind(access_type.to_string())
        .bind(granted_by)
        .bind(now)
        .bind(expires_at)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(SecretAccess {
            id,
            secret_id: secret_id.into(),
            user_id: user_id.into(),
            access_type,
            granted_by: granted_by.into(),
            granted_at: now,
            expires_at,
            revoked_at: None,
        })
    }

    async fn fetch_secret_row(&self, secret_id: &str) -> Result<Option<Secret>, String> {
        let row: Option<SecretRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, type, encrypted_value, version,
                    rotation_schedule, last_rotated_at, next_rotation_at,
                    created_by, created_at, updated_at, expires_at
             FROM secrets WHERE id = $1",
        )
        .bind(secret_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        match row {
            Some(r) => Ok(Some(r.into_secret()?)),
            None => Ok(None),
        }
    }

    async fn save_version(
        &self,
        secret_id: &str,
        version: i32,
        encrypted_value: &str,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO secret_versions (secret_id, version, encrypted_value, created_at)
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(secret_id)
        .bind(version)
        .bind(encrypted_value)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(())
    }

    async fn prune_versions(&self, secret_id: &str) -> Result<(), String> {
        let max_versions = self.config.max_versions_to_keep;
        sqlx::query(
            "DELETE FROM secret_versions
             WHERE secret_id = $1
               AND version NOT IN (
                 SELECT version FROM secret_versions
                 WHERE secret_id = $1
                 ORDER BY version DESC
                 LIMIT $2
               )",
        )
        .bind(secret_id)
        .bind(max_versions)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(())
    }

    async fn log_access(&self, secret_id: &str, user_id: &str, action: &str) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO secret_access_log (secret_id, user_id, action, accessed_at)
             VALUES ($1, $2, $3, NOW())",
        )
        .bind(secret_id)
        .bind(user_id)
        .bind(action)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(())
    }

    fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.cipher_key).map_err(|e| format!("Cipher init: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {e}"))?;

        // Pack:nonce (12) || ciphertext+tag
        let mut packed = Vec::with_capacity(12 + ciphertext.len());
        packed.extend_from_slice(&nonce_bytes);
        packed.extend_from_slice(&ciphertext);

        Ok(B64.encode(&packed))
    }

    fn decrypt(&self, encrypted: &str) -> Result<String, String> {
        let packed = B64
            .decode(encrypted)
            .map_err(|e| format!("Base64 decode: {e}"))?;

        if packed.len() < 12 {
            return Err("Encrypted data too short".into());
        }

        let nonce = Nonce::from_slice(&packed[..12]);
        let ciphertext = &packed[12..];

        let cipher =
            Aes256Gcm::new_from_slice(&self.cipher_key).map_err(|e| format!("Cipher init: {e}"))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {e}"))?;

        String::from_utf8(plaintext).map_err(|e| format!("UTF-8: {e}"))
    }
}

// ─── Key Derivation ────────────────────────────────────────────
//
// M-07: The KDF salt (SECRETS_KDF_SALT) is intentionally loaded via a regular
// environment variable rather than a secret store, because salts are not
// confidential — they serve to prevent precomputation attacks on the master key.
// The master encryption key itself must still be injected via a secure channel
// (e.g., AWS Secrets Manager, Vault, or Kubernetes Secrets mounted as env vars).
// In production, ensure SECRETS_KDF_SALT is set to a unique, randomly generated
// value of at least 16 characters.

fn derive_key(master_key: &str) -> Result<[u8; 32], String> {
    type HmacSha256 = Hmac<Sha256>;

    let salt = std::env::var("SECRETS_KDF_SALT")
        .map_err(|_| "SECRETS_KDF_SALT must be configured".to_string())?;

    if salt.len() < 16 {
        return Err("SECRETS_KDF_SALT must be at least 16 characters".to_string());
    }

    // HKDF-Extract(salt, ikm)
    let mut extract = <HmacSha256 as Mac>::new_from_slice(salt.as_bytes())
        .map_err(|e| format!("KDF salt init: {e}"))?;
    extract.update(master_key.as_bytes());
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand(prk, info, 32)
    let info = b"apexmail-secret-manager-encryption-key-v1";
    let mut expand =
        <HmacSha256 as Mac>::new_from_slice(&prk).map_err(|e| format!("KDF PRK init: {e}"))?;
    expand.update(info);
    expand.update(&[1]);
    let okm = expand.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    Ok(key)
}

// ─── Secret Generation ─────────────────────────────────────────

fn generate_secret_value(secret_type: SecretType) -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);

    match secret_type {
        SecretType::ApiKey => format!("am_{}", hex::encode(buf)),
        SecretType::WebhookSecret => format!("whsec_{}", hex::encode(buf)),
        SecretType::EncryptionKey => B64.encode(buf),
        _ => hex::encode(buf),
    }
}

// ─── Auto-Rotation Result ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AutoRotationResult {
    pub rotated: Vec<String>,
    pub errors: Vec<(String, String)>,
}

// ─── DB Row Helper ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SecretRow {
    id: String,
    tenant_id: String,
    name: String,
    #[sqlx(rename = "type")]
    secret_type: String,
    encrypted_value: String,
    version: i32,
    rotation_schedule: Option<serde_json::Value>,
    last_rotated_at: Option<chrono::DateTime<Utc>>,
    next_rotation_at: Option<chrono::DateTime<Utc>>,
    created_by: String,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

impl SecretRow {
    fn into_secret(self) -> Result<Secret, String> {
        let st: SecretType = match self.secret_type.as_str() {
            "api_key" => SecretType::ApiKey,
            "smtp_password" => SecretType::SmtpPassword,
            "webhook_secret" => SecretType::WebhookSecret,
            "encryption_key" => SecretType::EncryptionKey,
            "oauth_token" => SecretType::OauthToken,
            "certificate" => SecretType::Certificate,
            other => return Err(format!("Unknown secret type: {other}")),
        };

        let rotation_schedule: Option<RotationSchedule> = self
            .rotation_schedule
            .and_then(|v| serde_json::from_value(v).ok());

        Ok(Secret {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            secret_type: st,
            encrypted_value: self.encrypted_value,
            version: self.version,
            rotation_schedule,
            last_rotated_at: self.last_rotated_at,
            next_rotation_at: self.next_rotation_at,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_test_kdf_salt() {
        std::env::set_var("SECRETS_KDF_SALT", "apexmail-compliance-test-salt-v1");
    }

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn test_manager() -> Option<SecretManager> {
        ensure_test_kdf_salt();
        let _guard = test_runtime().enter();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        let config = SecretsConfig {
            encryption_key: "test-master-key-for-aes-encryption".into(),
            rotation_days: 90,
            max_versions_to_keep: 10,
        };
        let manager = SecretManager::new(pool, config);
        assert!(manager.is_ok(), "test secret manager should initialize");
        manager.ok()
    }

    #[test]
    fn test_derive_key_deterministic() {
        ensure_test_kdf_salt();
        let k1 = derive_key("same-key");
        let k2 = derive_key("same-key");
        assert!(k1.is_ok() && k2.is_ok(), "derive key should succeed");
        if let (Ok(k1), Ok(k2)) = (k1, k2) {
            assert_eq!(k1, k2);
        }
    }

    #[test]
    fn test_derive_key_different_keys() {
        ensure_test_kdf_salt();
        let k1 = derive_key("key-a");
        let k2 = derive_key("key-b");
        assert!(k1.is_ok() && k2.is_ok(), "derive key should succeed");
        if let (Ok(k1), Ok(k2)) = (k1, k2) {
            assert_ne!(k1, k2);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let plaintext = "my-secret-api-key-value";
        let encrypted = mgr.encrypt(plaintext).unwrap();
        let decrypted = mgr.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let plaintext = "same-value";
        let e1 = mgr.encrypt(plaintext).unwrap();
        let e2 = mgr.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertext
        assert_ne!(e1, e2);
        // Both decrypt to same value
        assert_eq!(mgr.decrypt(&e1).unwrap(), plaintext);
        assert_eq!(mgr.decrypt(&e2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_tampered_data_fails() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let encrypted = mgr.encrypt("secret").unwrap();
        let mut bytes = B64.decode(&encrypted).unwrap();
        // Tamper with ciphertext
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xFF;
        }
        let tampered = B64.encode(&bytes);
        assert!(mgr.decrypt(&tampered).is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let Some(mgr1) = test_manager() else {
            return;
        };
        let _guard = test_runtime().enter();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        let mgr2 = SecretManager::new(
            pool,
            SecretsConfig {
                encryption_key: "different-master-key-for-testing!!".into(),
                rotation_days: 90,
                max_versions_to_keep: 10,
            },
        );
        assert!(mgr2.is_ok(), "test secret manager should initialize");
        let Some(mgr2) = mgr2.ok() else {
            return;
        };

        let encrypted = mgr1.encrypt("secret-data").unwrap();
        assert!(mgr2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let short = B64.encode(b"short");
        assert!(mgr.decrypt(&short).is_err());
    }

    #[test]
    fn test_generate_api_key() {
        let val = generate_secret_value(SecretType::ApiKey);
        assert!(val.starts_with("am_"));
        assert!(val.len() > 10);
    }

    #[test]
    fn test_generate_webhook_secret() {
        let val = generate_secret_value(SecretType::WebhookSecret);
        assert!(val.starts_with("whsec_"));
    }

    #[test]
    fn test_generate_encryption_key() {
        let val = generate_secret_value(SecretType::EncryptionKey);
        // Base64 encoded
        assert!(B64.decode(&val).is_ok());
    }

    #[test]
    fn test_generate_unique() {
        let v1 = generate_secret_value(SecretType::SmtpPassword);
        let v2 = generate_secret_value(SecretType::SmtpPassword);
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_access_level_hierarchy() {
        assert!(AccessLevel::Admin.level() > AccessLevel::Write.level());
        assert!(AccessLevel::Write.level() > AccessLevel::Read.level());
        assert!(AccessLevel::Admin.level() >= AccessLevel::Read.level());
    }

    #[test]
    fn test_encrypt_empty_string() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let encrypted = mgr.encrypt("").unwrap();
        let decrypted = mgr.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_unicode() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let plaintext = "秘密のキー🔑";
        let encrypted = mgr.encrypt(plaintext).unwrap();
        let decrypted = mgr.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_value() {
        let Some(mgr) = test_manager() else {
            return;
        };
        let plaintext = "x".repeat(10_000);
        let encrypted = mgr.encrypt(&plaintext).unwrap();
        let decrypted = mgr.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
