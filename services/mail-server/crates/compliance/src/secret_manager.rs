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

// ─── DB-backed adversarial tests ────────────────────────────────────────────
//
// Secrets protect live credentials: the value must never leak into a list or
// audit response, access control must be enforced at every level, expiry and
// revocation must fail closed, and a tampered ciphertext must never decrypt.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;

    async fn manager(suffix: &str) -> Option<(PgPool, SecretManager)> {
        let pool = test_support::canonical_pool(
            &format!("secrets_{suffix}"),
            &format!("secrets_{suffix}"),
        )
        .await?;
        test_support::ensure_kdf_salt();
        let manager = SecretManager::new(
            pool.clone(),
            SecretsConfig {
                encryption_key: "unit-master-key-0123456789abcdef".into(),
                rotation_days: 90,
                max_versions_to_keep: 2,
            },
        )
        .expect("manager");
        Some((pool, manager))
    }

    async fn create(svc: &SecretManager, tenant: &str, name: &str, value: &str) -> Secret {
        svc.create_secret(&SecretCreateInput {
            tenant_id: tenant.into(),
            name: name.into(),
            secret_type: SecretType::ApiKey,
            value: Some(value.into()),
            created_by: "owner@apexmail.ee".into(),
            rotation_schedule: None,
            expires_at: None,
        })
        .await
        .expect("create")
    }

    #[tokio::test]
    async fn lifecycle_keeps_plaintext_out_of_metadata_and_prunes_versions() {
        let Some((pool, svc)) = manager("lifecycle").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let plaintext = "am_live_supersecret_value_0123456789";
        let secret = create(&svc, &tenant, "primary-api-key", plaintext).await;

        // The stored form is ciphertext, not the value.
        assert_ne!(secret.encrypted_value, plaintext);
        assert!(!secret.encrypted_value.contains(plaintext));

        // list() must never carry the plaintext (metadata + ciphertext only).
        let listed = svc.list_secrets(&tenant, None, 100, 0).await.expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, secret.id);
        assert!(!listed[0].encrypted_value.contains(plaintext));

        // The owner can read the value back exactly.
        let (_, value) = svc
            .get_secret(&secret.id, "owner@apexmail.ee")
            .await
            .expect("read")
            .expect("present");
        assert_eq!(value, plaintext);

        // Rotations bump the version and prune old versions to the cap.
        let (rotated, new_value) = svc
            .rotate_secret(&secret.id, "owner@apexmail.ee", Some("rotated-value-1"))
            .await
            .expect("rotate");
        assert_eq!(rotated.version, 2);
        assert_eq!(new_value, "rotated-value-1");
        assert!(rotated.last_rotated_at.is_some());
        svc.rotate_secret(&secret.id, "owner@apexmail.ee", Some("rotated-value-2"))
            .await
            .expect("rotate 2");
        svc.rotate_secret(&secret.id, "owner@apexmail.ee", Some("rotated-value-3"))
            .await
            .expect("rotate 3");

        let history = svc
            .get_version_history(&secret.id, "owner@apexmail.ee")
            .await
            .expect("history");
        let versions: Vec<i32> = history.iter().map(|(v, _)| *v).collect();
        assert_eq!(versions, vec![4, 3], "only max_versions_to_keep survive");
        // History is newest-first.
        assert!(history[0].1 >= history[1].1);

        // Rollback restores the value of the requested version exactly.
        let rolled = svc
            .rollback_to_version(&secret.id, 3, "owner@apexmail.ee")
            .await
            .expect("rollback");
        assert_eq!(rolled.version, 3);
        let (_, value) = svc
            .get_secret(&secret.id, "owner@apexmail.ee")
            .await
            .expect("read")
            .expect("present");
        assert_eq!(value, "rotated-value-2");

        // Rolling back to a pruned version is an explicit error.
        let err = svc
            .rollback_to_version(&secret.id, 1, "owner@apexmail.ee")
            .await
            .expect_err("pruned version must not resurrect");
        assert!(err.contains("Version not found"), "{err}");

        // The access log records every operation without the value.
        let actions: Vec<(String, String)> = sqlx::query_as(
            "SELECT action, user_id FROM secret_access_log WHERE secret_id = $1
             ORDER BY id",
        )
        .bind(&secret.id)
        .fetch_all(&pool)
        .await
        .expect("access log");
        let names: Vec<&str> = actions.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            names,
            vec!["read", "rotate", "rotate", "rotate", "rollback", "read"]
        );
        assert!(actions.iter().all(|(_, user)| user == "owner@apexmail.ee"));
    }

    #[tokio::test]
    async fn access_control_is_enforced_by_level_expiry_and_revocation() {
        let Some((_pool, svc)) = manager("access").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let secret = create(&svc, &tenant, "smtp-password", "hunter2-correct-horse").await;

        // A stranger has no access at all: even reads are denied.
        assert!(!svc
            .check_access(&secret.id, "stranger@other.test", AccessLevel::Read)
            .await
            .expect("check"));
        let err = svc
            .get_secret(&secret.id, "stranger@other.test")
            .await
            .expect_err("stranger read");
        assert!(err.contains("Access denied"), "{err}");
        assert!(svc
            .update_secret(
                &secret.id,
                "stranger@other.test",
                &SecretUpdateInput {
                    name: None,
                    rotation_schedule: None,
                    expires_at: None,
                }
            )
            .await
            .is_err());
        assert!(svc
            .delete_secret(&secret.id, "stranger@other.test")
            .await
            .is_err());
        assert!(svc
            .rotate_secret(&secret.id, "stranger@other.test", None)
            .await
            .is_err());
        assert!(svc
            .grant_access(
                &secret.id,
                "third@other.test",
                AccessLevel::Admin,
                "stranger@other.test",
                None
            )
            .await
            .is_err());
        assert!(svc
            .revoke_access(&secret.id, "owner@apexmail.ee", "stranger@other.test")
            .await
            .is_err());

        // Read-only grants can read, but not write, rotate or delete.
        svc.grant_access(
            &secret.id,
            "reader@apexmail.ee",
            AccessLevel::Read,
            "owner@apexmail.ee",
            None,
        )
        .await
        .expect("grant read");
        assert!(svc
            .get_secret(&secret.id, "reader@apexmail.ee")
            .await
            .expect("read")
            .is_some());
        assert!(svc
            .rotate_secret(&secret.id, "reader@apexmail.ee", Some("x"))
            .await
            .is_err());
        assert!(svc
            .delete_secret(&secret.id, "reader@apexmail.ee")
            .await
            .is_err());

        // An expired grant is no grant (the DB clock decides).
        svc.grant_access(
            &secret.id,
            "expired@apexmail.ee",
            AccessLevel::Admin,
            "owner@apexmail.ee",
            Some(Utc::now() - Duration::seconds(5)),
        )
        .await
        .expect("grant expired");
        assert!(!svc
            .check_access(&secret.id, "expired@apexmail.ee", AccessLevel::Read)
            .await
            .expect("check"));

        // Revocation takes effect immediately for a previously valid grant.
        svc.grant_access(
            &secret.id,
            "temp@apexmail.ee",
            AccessLevel::Write,
            "owner@apexmail.ee",
            None,
        )
        .await
        .expect("grant write");
        svc.rotate_secret(&secret.id, "temp@apexmail.ee", Some("temp-rotation"))
            .await
            .expect("write allowed");
        svc.revoke_access(&secret.id, "temp@apexmail.ee", "owner@apexmail.ee")
            .await
            .expect("revoke");
        let err = svc
            .rotate_secret(&secret.id, "temp@apexmail.ee", Some("nope"))
            .await
            .expect_err("revoked must fail");
        assert!(err.contains("Access denied"), "{err}");
        // Re-granting the same user revives the row rather than duplicating it.
        svc.grant_access(
            &secret.id,
            "temp@apexmail.ee",
            AccessLevel::Write,
            "owner@apexmail.ee",
            None,
        )
        .await
        .expect("regrant");
        svc.rotate_secret(&secret.id, "temp@apexmail.ee", Some("re-granted"))
            .await
            .expect("write allowed after regrant");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secret_access WHERE secret_id = $1 AND user_id = 'temp@apexmail.ee'",
        )
        .bind(&secret.id)
        .fetch_one(&_pool)
        .await
        .expect("count");
        assert_eq!(rows, 1, "grant/revoke must not duplicate access rows");
    }

    #[tokio::test]
    async fn expiry_refuses_reads_and_writes_fail_closed() {
        let Some((pool, svc)) = manager("expiry").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let secret = create(&svc, &tenant, "expiring", "value-that-expires").await;
        sqlx::query("UPDATE secrets SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1")
            .bind(&secret.id)
            .execute(&pool)
            .await
            .expect("expire");
        let err = svc
            .get_secret(&secret.id, "owner@apexmail.ee")
            .await
            .expect_err("expired read must fail");
        assert!(err.contains("expired"), "{err}");
        // The metadata-only read (fetch) still works for auditors.
        assert!(svc
            .get_version_history(&secret.id, "owner@apexmail.ee")
            .await
            .is_ok());

        // Metadata update can extend the expiry and restore reads.
        let updated = svc
            .update_secret(
                &secret.id,
                "owner@apexmail.ee",
                &SecretUpdateInput {
                    name: Some("expiring-renamed".into()),
                    rotation_schedule: Some(RotationSchedule {
                        interval_days: 30,
                        auto_rotate: true,
                        notify_before_days: 7,
                    }),
                    expires_at: Some(Utc::now() + Duration::days(1)),
                },
            )
            .await
            .expect("update");
        assert_eq!(updated.name, "expiring-renamed");
        assert!(updated.next_rotation_at.is_some());
        assert_eq!(
            updated.rotation_schedule.as_ref().map(|r| r.interval_days),
            Some(30)
        );
        assert!(svc
            .get_secret(&secret.id, "owner@apexmail.ee")
            .await
            .expect("read after extension")
            .is_some());

        // A corrupt rotation_schedule in the row degrades to None rather than
        // poisoning every read of the secret.
        sqlx::query("UPDATE secrets SET rotation_schedule = '\"garbage\"'::jsonb WHERE id = $1")
            .bind(&secret.id)
            .execute(&pool)
            .await
            .expect("corrupt schedule");
        let listed = svc.list_secrets(&tenant, None, 10, 0).await.expect("list");
        assert!(listed[0].rotation_schedule.is_none());

        // An unknown secret type is an explicit error, never a coerced type.
        sqlx::query("UPDATE secrets SET type = 'totally_unknown' WHERE id = $1")
            .bind(&secret.id)
            .execute(&pool)
            .await
            .expect("corrupt type");
        let err = svc
            .list_secrets(&tenant, None, 10, 0)
            .await
            .expect_err("unknown type must be reported");
        assert!(err.contains("Unknown secret type"), "{err}");
    }

    #[tokio::test]
    async fn tampered_ciphertext_in_every_region_fails_closed() {
        let Some((pool, svc)) = manager("tamper").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let secret = create(&svc, &tenant, "tamper-me", "original-secret-value").await;

        let original = secret.encrypted_value.clone();
        let bytes = B64.decode(&original).expect("base64");
        assert!(bytes.len() >= 12 + 16, "nonce + ciphertext+tag");

        // Flip a bit in the nonce, in the ciphertext body, and in the tag.
        for (label, index) in [
            ("nonce", 0usize),
            ("nonce-last", 11),
            ("ciphertext", 12),
            ("tag", bytes.len() - 1),
        ] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            sqlx::query("UPDATE secrets SET encrypted_value = $1 WHERE id = $2")
                .bind(B64.encode(&tampered))
                .bind(&secret.id)
                .execute(&pool)
                .await
                .expect("tamper");
            let err = svc
                .get_secret(&secret.id, "owner@apexmail.ee")
                .await
                .expect_err(&format!("{label} tamper must fail closed"));
            assert!(
                err.contains("Decryption failed") || err.contains("too short"),
                "{label}: {err}"
            );
        }

        // Truncation/empty payloads are refused, not decoded as empty secrets.
        for bad in ["", &original[..8], "!!!not-base64!!!"] {
            sqlx::query("UPDATE secrets SET encrypted_value = $1 WHERE id = $2")
                .bind(bad)
                .bind(&secret.id)
                .execute(&pool)
                .await
                .expect("corrupt");
            assert!(
                svc.get_secret(&secret.id, "owner@apexmail.ee")
                    .await
                    .is_err(),
                "value {bad:?} must not decrypt"
            );
        }

        // A different master key can never decrypt this secret's ciphertext.
        sqlx::query("UPDATE secrets SET encrypted_value = $1 WHERE id = $2")
            .bind(&original)
            .bind(&secret.id)
            .execute(&pool)
            .await
            .expect("restore");
        test_support::ensure_kdf_salt();
        let other = SecretManager::new(
            pool.clone(),
            SecretsConfig {
                encryption_key: "a-completely-different-master".into(),
                rotation_days: 90,
                max_versions_to_keep: 2,
            },
        )
        .expect("other manager");
        let err = other
            .get_secret(&secret.id, "owner@apexmail.ee")
            .await
            .expect_err("wrong key must fail");
        assert!(err.contains("Decryption failed"), "{err}");
    }

    #[tokio::test]
    async fn rotation_scan_only_rotates_due_auto_schedules() {
        let Some((pool, svc)) = manager("rotation").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let due_auto = create(&svc, &tenant, "due-auto", "old-1").await;
        let due_manual = create(&svc, &tenant, "due-manual", "old-2").await;
        let future_auto = create(&svc, &tenant, "future-auto", "old-3").await;

        let schedule = |auto_rotate: bool| RotationSchedule {
            interval_days: 90,
            auto_rotate,
            notify_before_days: 7,
        };
        sqlx::query(
            "UPDATE secrets SET rotation_schedule = $1, next_rotation_at = NOW() - INTERVAL '1 day'
             WHERE id = $2",
        )
        .bind(serde_json::to_value(schedule(true)).unwrap())
        .bind(&due_auto.id)
        .execute(&pool)
        .await
        .expect("due auto");
        sqlx::query(
            "UPDATE secrets SET rotation_schedule = $1, next_rotation_at = NOW() - INTERVAL '1 day'
             WHERE id = $2",
        )
        .bind(serde_json::to_value(schedule(false)).unwrap())
        .bind(&due_manual.id)
        .execute(&pool)
        .await
        .expect("due manual");
        sqlx::query(
            "UPDATE secrets SET rotation_schedule = $1, next_rotation_at = NOW() + INTERVAL '30 days'
             WHERE id = $2",
        )
        .bind(serde_json::to_value(schedule(true)).unwrap())
        .bind(&future_auto.id)
        .execute(&pool)
        .await
        .expect("future auto");

        let due = svc.get_secrets_for_rotation().await.expect("due");
        let due_ids: Vec<&str> = due.iter().map(|s| s.id.as_str()).collect();
        assert!(due_ids.contains(&due_auto.id.as_str()));
        assert!(due_ids.contains(&due_manual.id.as_str()));
        assert!(!due_ids.contains(&future_auto.id.as_str()));

        let result = svc.process_auto_rotations().await.expect("rotations");
        assert_eq!(result.rotated, vec![due_auto.id.clone()]);
        assert!(result.errors.is_empty(), "{:?}", result.errors);

        // The manual schedule was only left in the scan: its version is
        // untouched until a human rotates it.
        let (result_manual, _) = svc
            .get_secret(&due_manual.id, "owner@apexmail.ee")
            .await
            .expect("read manual")
            .expect("present");
        assert_eq!(result_manual.version, 1);
        let (result_auto, auto_value) = svc
            .get_secret(&due_auto.id, "owner@apexmail.ee")
            .await
            .expect("read auto")
            .expect("present");
        assert_eq!(result_auto.version, 2);
        // Auto-rotation generates a fresh key of the declared type.
        assert!(auto_value.starts_with("am_"));
        assert_ne!(auto_value, "old-1");
        // The next rotation moves forward from now.
        assert!(result_auto.next_rotation_at.expect("next") > Utc::now());
    }

    #[tokio::test]
    async fn names_are_tenant_scoped_and_deletion_archives() {
        let Some((pool, svc)) = manager("tenant").await else {
            return;
        };
        let tenant_a = test_support::unique_tenant();
        let tenant_b = test_support::unique_tenant();
        let a = create(&svc, &tenant_a, "shared-name", "tenant-a-value").await;
        let b = create(&svc, &tenant_b, "shared-name", "tenant-b-value").await;
        assert_ne!(a.id, b.id);

        // Name lookups resolve only within the requested tenant.
        let (found_a, value_a) = svc
            .get_secret_by_name(&tenant_a, "shared-name", "owner@apexmail.ee")
            .await
            .expect("lookup a")
            .expect("present");
        assert_eq!(found_a.id, a.id);
        assert_eq!(value_a, "tenant-a-value");
        let (found_b, value_b) = svc
            .get_secret_by_name(&tenant_b, "shared-name", "owner@apexmail.ee")
            .await
            .expect("lookup b")
            .expect("present");
        assert_eq!(found_b.id, b.id);
        assert_eq!(value_b, "tenant-b-value");
        assert!(svc
            .get_secret_by_name(&tenant_a, "not-there", "owner@apexmail.ee")
            .await
            .expect("missing")
            .is_none());

        // Listing one tenant never returns the other's rows, and the type
        // filter is applied server-side.
        let listed = svc
            .list_secrets(&tenant_a, Some(SecretType::ApiKey), 100, 0)
            .await
            .expect("list filtered");
        assert!(listed.iter().all(|s| s.tenant_id == tenant_a));
        assert_eq!(listed.len(), 1);
        let listed_other_type = svc
            .list_secrets(&tenant_a, Some(SecretType::Certificate), 100, 0)
            .await
            .expect("list other type");
        assert!(listed_other_type.is_empty());

        // Deletion archives the row before removing it.
        svc.delete_secret(&a.id, "owner@apexmail.ee")
            .await
            .expect("delete");
        assert!(svc
            .get_secret(&a.id, "owner@apexmail.ee")
            .await
            .expect_err("deleted secret is gone")
            .contains("Access denied"));
        let archived: (String, String) =
            sqlx::query_as("SELECT id, encrypted_value FROM secrets_archive WHERE id = $1")
                .bind(&a.id)
                .fetch_one(&pool)
                .await
                .expect("archived row");
        assert_eq!(archived.0, a.id);
        assert_ne!(
            archived.1, "tenant-a-value",
            "archive keeps ciphertext only"
        );
        // The other tenant's row is untouched.
        assert!(svc
            .get_secret(&b.id, "owner@apexmail.ee")
            .await
            .expect("b survives")
            .is_some());
        // Deleting an already-deleted secret is refused (no fabricated success).
        assert!(svc.delete_secret(&a.id, "owner@apexmail.ee").await.is_err());
    }

    #[tokio::test]
    async fn duplicate_names_and_hostile_metadata_are_reported_not_swallowed() {
        let Some((_pool, svc)) = manager("hostile").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        create(&svc, &tenant, "dup", "one").await;
        let err = svc
            .create_secret(&SecretCreateInput {
                tenant_id: tenant.clone(),
                name: "dup".into(),
                secret_type: SecretType::WebhookSecret,
                value: Some("two".into()),
                created_by: "owner@apexmail.ee".into(),
                rotation_schedule: None,
                expires_at: None,
            })
            .await
            .expect_err("duplicate name must be a DB error");
        assert!(err.contains("DB error"), "{err}");

        // Auto-generated values follow the type's contract.
        let generated = svc
            .create_secret(&SecretCreateInput {
                tenant_id: tenant.clone(),
                name: "generated-webhook".into(),
                secret_type: SecretType::WebhookSecret,
                value: None,
                created_by: "owner@apexmail.ee".into(),
                rotation_schedule: None,
                expires_at: None,
            })
            .await
            .expect("generate");
        let (_, value) = svc
            .get_secret(&generated.id, "owner@apexmail.ee")
            .await
            .expect("read")
            .expect("present");
        assert!(value.starts_with("whsec_"), "{value}");

        // Hostile names (unicode, empty, very long) are persisted verbatim and
        // never confuse the tenant-scoped lookup.
        let hostile_name = format!("名前/../../{}", "x".repeat(300));
        let hostile = create(&svc, &tenant, &hostile_name, "hostile-value").await;
        let (found, value) = svc
            .get_secret_by_name(&tenant, &hostile_name, "owner@apexmail.ee")
            .await
            .expect("lookup")
            .expect("present");
        assert_eq!(found.id, hostile.id);
        assert_eq!(value, "hostile-value");
        // A tenant-less lookup never matches another tenant's hostile name.
        assert!(svc
            .get_secret_by_name(
                &test_support::unique_tenant(),
                &hostile_name,
                "owner@apexmail.ee"
            )
            .await
            .expect("other tenant")
            .is_none());

        // Unknown type filter values are not a way to list everything.
        assert!(svc
            .list_secrets(&tenant, Some(SecretType::OauthToken), 100, 0)
            .await
            .expect("filter")
            .is_empty());
    }
}
