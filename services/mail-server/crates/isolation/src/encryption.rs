//! Encryption:AES-256-GCM envelope encryption with key rotation.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::SecurityConfig;
use crate::types::*;

const ALGORITHM: &str = "aes-256-gcm";
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 12;

fn fill_os_random(bytes: &mut [u8]) -> anyhow::Result<()> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|e| anyhow::anyhow!("OsRng failed while generating isolation encryption material: {e}"))
}

// ── Key Derivation ─────────────────────────────────────────

fn derive_key(master_key: &str, salt: &[u8], info: &str) -> anyhow::Result<[u8; KEY_LENGTH]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key.as_bytes());
    let mut okm = [0u8; KEY_LENGTH];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(okm)
}

fn hash_code(s: &str) -> i64 {
    let digest = Sha256::digest(format!("apexmail:isolation:lock:{s}").as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(bytes) & 0x7fff_ffff_ffff_ffff) as i64
}

// ── Encryption Service ─────────────────────────────────────

pub struct EncryptionService {
    db: PgPool,
    config: SecurityConfig,
    keys: dashmap::DashMap<String, EncryptionKey>,
    active_key_by_org: dashmap::DashMap<String, String>,
    policies: dashmap::DashMap<String, EncryptionPolicy>,
}

impl EncryptionService {
    pub fn new(db: PgPool, config: SecurityConfig) -> Self {
        Self {
            db,
            config,
            keys: dashmap::DashMap::new(),
            active_key_by_org: dashmap::DashMap::new(),
            policies: dashmap::DashMap::new(),
        }
    }

    pub async fn initialize(&self) -> anyhow::Result<()> {
        self.load_active_keys().await?;
        self.load_policies().await?;
        self.check_key_rotation().await?;
        info!(
            keys = self.keys.len(),
            policies = self.policies.len(),
            "Encryption service initialized"
        );
        Ok(())
    }

    // ── Data Key Encryption ────────────────────────────────

    fn encrypt_data_key(&self, raw_key: &[u8]) -> anyhow::Result<String> {
        let salt = b"apexmail-isolation-master";
        let derived = derive_key(&self.config.encryption_key, salt, "data-key-encryption")?;

        let cipher = Aes256Gcm::new_from_slice(&derived)?;
        let mut iv = [0u8; IV_LENGTH];
        fill_os_random(&mut iv)?;
        let nonce = Nonce::from_slice(&iv);

        let mut buffer = raw_key.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        Ok(format!(
            "{}:{}:{}",
            B64.encode(iv),
            B64.encode(tag),
            B64.encode(buffer)
        ))
    }

    fn decrypt_data_key(&self, encrypted: &str) -> anyhow::Result<Vec<u8>> {
        let parts: Vec<&str> = encrypted.split(':').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid encrypted key format");
        }
        let iv = B64.decode(parts[0])?;
        let tag_bytes = B64.decode(parts[1])?;
        let mut buffer = B64.decode(parts[2])?;

        let salt = b"apexmail-isolation-master";
        let derived = derive_key(&self.config.encryption_key, salt, "data-key-encryption")?;

        let cipher = Aes256Gcm::new_from_slice(&derived)?;
        let nonce = Nonce::from_slice(&iv);

        let tag = Tag::from_slice(&tag_bytes);
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    // ── Key Management ─────────────────────────────────────

    pub async fn generate_data_key(&self, organization_id: &str) -> anyhow::Result<EncryptionKey> {
        let mut tx = self.db.begin().await?;
        let key = self.generate_data_key_tx(&mut tx, organization_id).await?;
        tx.commit().await?;
        Ok(key)
    }

    pub async fn encrypt(
        &self,
        organization_id: &str,
        plaintext: &str,
    ) -> anyhow::Result<EncryptedField> {
        let key = self.get_or_create_active_key(organization_id).await?;
        let raw_key = self.decrypt_data_key(&key.encrypted_key)?;

        let cipher = Aes256Gcm::new_from_slice(&raw_key)?;
        let mut iv = [0u8; IV_LENGTH];
        fill_os_random(&mut iv)?;
        let nonce = Nonce::from_slice(&iv);

        let mut buffer = plaintext.as_bytes().to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedField {
            ciphertext: B64.encode(buffer),
            key_id: key.id.clone(),
            algorithm: ALGORITHM.into(),
            iv: B64.encode(iv),
            auth_tag: B64.encode(tag),
        })
    }

    pub async fn decrypt(&self, encrypted: &EncryptedField) -> anyhow::Result<String> {
        let key = self.get_key_by_id(&encrypted.key_id).await?;
        let raw_key = self.decrypt_data_key(&key.encrypted_key)?;

        let cipher = Aes256Gcm::new_from_slice(&raw_key)?;
        let iv = B64.decode(&encrypted.iv)?;
        let mut buffer = B64.decode(&encrypted.ciphertext)?;
        let tag_bytes = B64.decode(&encrypted.auth_tag)?;

        let nonce = Nonce::from_slice(&iv);
        let tag = Tag::from_slice(&tag_bytes);
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
            .map_err(|e| anyhow::anyhow!("Decryption failed (possibly tampered): {}", e))?;

        String::from_utf8(buffer).map_err(Into::into)
    }

    /// Encrypt specific fields of an object based on policy.
    pub async fn encrypt_object(
        &self,
        organization_id: &str,
        resource: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let Some(policy) = self.get_policy_for_resource(resource) else {
            return Ok(data.clone());
        };
        let mut result = data.clone();

        if let Some(obj) = result.as_object_mut() {
            for field in &policy.fields {
                if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                    let encrypted = self.encrypt(organization_id, val).await?;
                    obj.insert(field.clone(), serde_json::to_value(&encrypted)?);
                }
            }
        }
        Ok(result)
    }

    /// Decrypt specific fields of an object based on policy.
    pub async fn decrypt_object(
        &self,
        resource: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let Some(policy) = self.get_policy_for_resource(resource) else {
            return Ok(data.clone());
        };
        let mut result = data.clone();

        if let Some(obj) = result.as_object_mut() {
            for field in &policy.fields {
                if let Some(val) = obj.get(field) {
                    if let Ok(enc) = serde_json::from_value::<EncryptedField>(val.clone()) {
                        let decrypted = self.decrypt(&enc).await?;
                        obj.insert(field.clone(), serde_json::Value::String(decrypted));
                    }
                }
            }
        }
        Ok(result)
    }

    /// Rotate key for an organization with advisory lock.
    pub async fn rotate_key(&self, organization_id: &str) -> anyhow::Result<EncryptionKey> {
        let lock_id = hash_code(organization_id);
        let mut lock_conn = self.db.acquire().await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_id)
            .execute(&mut *lock_conn)
            .await?;

        let rotation_result: anyhow::Result<EncryptionKey> = async {
            let old_key_id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM iso_encryption_keys WHERE organization_id=$1 AND status='active'",
            )
            .bind(organization_id)
            .fetch_optional(&mut *lock_conn)
            .await?;

            let new_key = self.generate_data_key(organization_id).await?;
            if let Some(old_id) = old_key_id.as_deref() {
                self.reencrypt_data(organization_id, old_id, &new_key.id)
                    .await?;
            }
            Ok(new_key)
        }
        .await;

        if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_id)
            .execute(&mut *lock_conn)
            .await
        {
            warn!(org_id = organization_id, error = %e, "Failed to release advisory lock");
        }

        let new_key = rotation_result?;
        info!(org_id = organization_id, "Key rotation completed");
        Ok(new_key)
    }

    /// Create a new encryption policy.
    pub async fn create_policy(
        &self,
        policy: EncryptionPolicy,
    ) -> anyhow::Result<EncryptionPolicy> {
        sqlx::query(
            "INSERT INTO iso_encryption_policies (id, name, resource, fields, algorithm, key_rotation_days, enabled)
             VALUES ($1,$2,$3,$4,$5,$6,$7)"
        )
            .bind(&policy.id).bind(&policy.name).bind(&policy.resource)
            .bind(serde_json::to_value(&policy.fields)?).bind(&policy.algorithm)
            .bind(policy.key_rotation_days).bind(policy.enabled)
            .execute(&self.db)
            .await?;

        self.policies
            .insert(policy.resource.clone(), policy.clone());
        Ok(policy)
    }

    /// SHA-256 hash for searchable encryption.
    pub fn hash(value: &str, salt: Option<&str>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        if let Some(s) = salt {
            hasher.update(s.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Generate a cryptographically random hex token.
    pub fn try_generate_token(length: usize) -> anyhow::Result<String> {
        let byte_len = length / 2;
        let mut bytes = vec![0u8; byte_len];
        fill_os_random(&mut bytes)?;
        Ok(hex::encode(&bytes))
    }

    /// Generate a cryptographically random hex token.
    ///
    /// Prefer [`Self::try_generate_token`] in fallible request paths. This
    /// compatibility wrapper preserves existing callers and tests.
    pub fn generate_token(length: usize) -> String {
        Self::try_generate_token(length).expect("OsRng must be available for token generation")
    }

    // ── Private ────────────────────────────────────────────

    async fn load_active_keys(&self) -> anyhow::Result<()> {
        let rows: Vec<(String, String, i32, String, Vec<u8>, String, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>)> =
            sqlx::query_as(
                "SELECT id, organization_id, version, algorithm, key_material, status, created_at, rotated_at, expires_at
                 FROM iso_encryption_keys WHERE status = 'active'"
            )
            .fetch_all(&self.db)
            .await?;

        for (
            id,
            org_id,
            version,
            algorithm,
            key_material,
            status,
            created_at,
            rotated_at,
            expires_at,
        ) in rows
        {
            let key = EncryptionKey {
                id: id.clone(),
                organization_id: org_id,
                version,
                algorithm,
                encrypted_key: String::from_utf8_lossy(&key_material).into(),
                status: KeyStatus::parse(&status).unwrap_or(KeyStatus::Active),
                created_at,
                rotated_at,
                expires_at,
            };
            self.active_key_by_org
                .insert(key.organization_id.clone(), id.clone());
            self.keys.insert(id, key);
        }
        Ok(())
    }

    async fn load_policies(&self) -> anyhow::Result<()> {
        let rows: Vec<(String, String, String, serde_json::Value, String, i64, bool)> =
            sqlx::query_as(
                "SELECT id, name, resource, fields, algorithm, key_rotation_days, enabled
                 FROM iso_encryption_policies WHERE enabled = true",
            )
            .fetch_all(&self.db)
            .await?;

        for (id, name, resource, fields, algorithm, rotation_days, enabled) in rows {
            let policy = EncryptionPolicy {
                id,
                name,
                resource: resource.clone(),
                fields: serde_json::from_value(fields).unwrap_or_default(),
                algorithm,
                key_rotation_days: rotation_days,
                enabled,
            };
            self.policies.insert(resource, policy);
        }
        Ok(())
    }

    async fn check_key_rotation(&self) -> anyhow::Result<()> {
        let threshold = Utc::now() + chrono::Duration::days(7);
        for entry in self.keys.iter() {
            let key = entry.value();
            if let Some(expires) = key.expires_at {
                if expires < threshold {
                    warn!(
                        key_id = key.id,
                        org_id = key.organization_id,
                        "Encryption key expiring soon"
                    );
                }
            }
        }
        Ok(())
    }

    async fn get_or_create_active_key(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<EncryptionKey> {
        if let Some(key_id) = self.active_key_by_org.get(organization_id) {
            if let Some(key) = self.keys.get(key_id.value()) {
                if key.status == KeyStatus::Active {
                    return Ok(key.clone());
                }
            }
        }

        // Check DB
        let row: Option<(String, String, i32, String, Vec<u8>, String, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>)> =
            sqlx::query_as(
                "SELECT id, organization_id, version, algorithm, key_material, status, created_at, rotated_at, expires_at
                 FROM iso_encryption_keys WHERE organization_id=$1 AND status='active' ORDER BY version DESC LIMIT 1"
            )
            .bind(organization_id)
            .fetch_optional(&self.db)
            .await?;

        if let Some((
            id,
            org_id,
            version,
            algorithm,
            key_material,
            status,
            created_at,
            rotated_at,
            expires_at,
        )) = row
        {
            let key = EncryptionKey {
                id: id.clone(),
                organization_id: org_id,
                version,
                algorithm,
                encrypted_key: String::from_utf8_lossy(&key_material).into(),
                status: KeyStatus::parse(&status).unwrap_or(KeyStatus::Active),
                created_at,
                rotated_at,
                expires_at,
            };
            self.active_key_by_org
                .insert(organization_id.to_string(), id.clone());
            self.keys.insert(id, key.clone());
            return Ok(key);
        }

        // No key found—generate one
        self.generate_data_key(organization_id).await
    }

    async fn get_key_by_id(&self, key_id: &str) -> anyhow::Result<EncryptionKey> {
        if let Some(cached) = self.keys.get(key_id) {
            return Ok(cached.clone());
        }

        let row: (String, String, i32, String, Vec<u8>, String, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as(
                "SELECT id, organization_id, version, algorithm, key_material, status, created_at, rotated_at, expires_at
                 FROM iso_encryption_keys WHERE id=$1"
            )
            .bind(key_id)
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Encryption key not found: {}", key_id))?;

        let key = EncryptionKey {
            id: row.0.clone(),
            organization_id: row.1,
            version: row.2,
            algorithm: row.3,
            encrypted_key: String::from_utf8_lossy(&row.4).into(),
            status: KeyStatus::parse(&row.5).unwrap_or(KeyStatus::Retired),
            created_at: row.6,
            rotated_at: row.7,
            expires_at: row.8,
        };
        if key.status == KeyStatus::Active {
            self.active_key_by_org
                .insert(key.organization_id.clone(), key.id.clone());
        }
        self.keys.insert(key.id.clone(), key.clone());
        Ok(key)
    }

    async fn generate_data_key_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        organization_id: &str,
    ) -> anyhow::Result<EncryptionKey> {
        let mut raw_key = [0u8; KEY_LENGTH];
        fill_os_random(&mut raw_key)?;

        let encrypted_key = self.encrypt_data_key(&raw_key)?;

        let version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM iso_encryption_keys WHERE organization_id = $1"
        )
            .bind(organization_id)
            .fetch_one(&mut **tx)
            .await?;

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(self.config.data_key_rotation_days);

        sqlx::query(
            "UPDATE iso_encryption_keys SET status='retired' WHERE organization_id=$1 AND status='active'"
        )
            .bind(organization_id)
            .execute(&mut **tx)
            .await?;

        sqlx::query(
            "INSERT INTO iso_encryption_keys (id, organization_id, version, algorithm, key_material, status, created_at, expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
        )
            .bind(&id).bind(organization_id).bind(version)
            .bind(ALGORITHM).bind(encrypted_key.as_bytes())
            .bind("active").bind(now).bind(expires_at)
            .execute(&mut **tx)
            .await?;

        let key = EncryptionKey {
            id: id.clone(),
            organization_id: organization_id.into(),
            version,
            algorithm: ALGORITHM.into(),
            encrypted_key,
            status: KeyStatus::Active,
            created_at: now,
            rotated_at: None,
            expires_at: Some(expires_at),
        };

        self.active_key_by_org
            .insert(organization_id.to_string(), id.clone());
        self.keys.insert(id, key.clone());
        info!(
            org_id = organization_id,
            version = version,
            "Data key generated"
        );
        Ok(key)
    }

    async fn reencrypt_data(
        &self,
        organization_id: &str,
        old_key_id: &str,
        new_key_id: &str,
    ) -> anyhow::Result<()> {
        info!(
            org_id = organization_id,
            old_key = old_key_id,
            new_key = new_key_id,
            "Starting re-encryption"
        );

        // Get old and new keys
        let old_key = self.get_key_by_id(old_key_id).await?;
        let new_key = self.get_key_by_id(new_key_id).await?;

        // Decrypt the raw key material for both keys
        let old_raw = self.decrypt_data_key(&old_key.encrypted_key)?;
        let new_raw = self.decrypt_data_key(&new_key.encrypted_key)?;

        let old_cipher = Aes256Gcm::new_from_slice(&old_raw)?;
        let new_cipher = Aes256Gcm::new_from_slice(&new_raw)?;

        // Get all enabled policies to find encrypted resources/fields
        let policies: Vec<EncryptionPolicy> =
            self.policies.iter().map(|e| e.value().clone()).collect();

        let mut total_reencrypted = 0u64;

        for policy in policies {
            // Map resource to table name (convention:iso_<resource>)
            let table = format!("iso_{}", policy.resource.replace('-', "_"));
            if !is_safe_ident(&table) {
                warn!(
                    table = table,
                    "Skipping re-encryption for unsafe table identifier"
                );
                continue;
            }

            for field in &policy.fields {
                if !is_safe_ident(field) {
                    warn!(
                        field = field,
                        "Skipping re-encryption for unsafe field identifier"
                    );
                    continue;
                }
                // Find records where the JSONB field has our old key_id
                // The encrypted field structure:{"ciphertext":"...", "key_id":"...", "algorithm":"...", "iv":"...", "auth_tag":"..."}
                let query = format!(
                    "SELECT id, {field} FROM {table} WHERE organization_id = $1 AND {field}->>'key_id' = $2",
                    field = field,
                    table = table
                );

                let rows: Vec<(String, serde_json::Value)> = match sqlx::query_as(&query)
                    .bind(organization_id)
                    .bind(old_key_id)
                    .fetch_all(&self.db)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        // Table might not exist or schema mismatch - log and continue
                        warn!(
                            table = table,
                            field = field,
                            error = %e,
                            "Skipping re-encryption for field"
                        );
                        continue;
                    }
                };

                let mut updates: Vec<(String, serde_json::Value)> = Vec::with_capacity(rows.len());

                for (record_id, encrypted_value) in rows {
                    // Parse the encrypted field
                    let enc_field: EncryptedField = match serde_json::from_value(encrypted_value) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!(record_id = record_id, error = %e, "Failed to parse encrypted field");
                            continue;
                        }
                    };

                    // Decrypt with old key
                    let iv = match B64.decode(&enc_field.iv) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(record_id = record_id, error = %e, "Failed to decode IV");
                            continue;
                        }
                    };
                    let auth_tag = match B64.decode(&enc_field.auth_tag) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(record_id = record_id, error = %e, "Failed to decode auth tag");
                            continue;
                        }
                    };
                    let ciphertext = match B64.decode(&enc_field.ciphertext) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(record_id = record_id, error = %e, "Failed to decode ciphertext");
                            continue;
                        }
                    };

                    let nonce = Nonce::from_slice(&iv);
                    let tag = Tag::from_slice(&auth_tag);
                    let mut buffer = ciphertext.clone();
                    if let Err(e) =
                        old_cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
                    {
                        warn!(record_id = record_id, error = %e, "Failed to decrypt field");
                        continue;
                    }

                    // Re-encrypt with new key
                    let mut new_iv = [0u8; IV_LENGTH];
                    fill_os_random(&mut new_iv)?;
                    let new_nonce = Nonce::from_slice(&new_iv);

                    let mut buffer = buffer;
                    let new_tag = match new_cipher.encrypt_in_place_detached(
                        new_nonce,
                        b"",
                        &mut buffer,
                    ) {
                        Ok(tag) => tag,
                        Err(e) => {
                            warn!(record_id = record_id, error = %e, "Failed to re-encrypt field");
                            continue;
                        }
                    };

                    let new_enc_field = EncryptedField {
                        ciphertext: B64.encode(buffer),
                        key_id: new_key_id.to_string(),
                        algorithm: ALGORITHM.to_string(),
                        iv: B64.encode(new_iv),
                        auth_tag: B64.encode(new_tag),
                    };

                    updates.push((record_id, serde_json::to_value(&new_enc_field)?));

                    total_reencrypted += 1;
                }

                for chunk in updates.chunks(250) {
                    let mut qb = QueryBuilder::<Postgres>::new(format!(
                        "UPDATE {table} AS t SET {field} = u.val FROM (",
                        table = table,
                        field = field
                    ));

                    qb.push("VALUES ");
                    let mut separated = qb.separated(", ");
                    for (id, value) in chunk {
                        separated.push("(");
                        separated.push_bind(id);
                        separated.push(", ");
                        separated.push_bind(value);
                        separated.push(")");
                    }
                    drop(separated);

                    qb.push(") AS u(id, val) WHERE t.id = u.id");

                    if let Err(e) = qb.build().execute(&self.db).await {
                        warn!(table = table, field = field, error = %e, "Batch update failed during re-encryption");
                    }
                }
            }
        }

        info!(
            org_id = organization_id,
            records = total_reencrypted,
            "Re-encryption completed"
        );
        Ok(())
    }

    fn get_policy_for_resource(&self, resource: &str) -> Option<EncryptionPolicy> {
        self.policies.get(resource).map(|e| e.value().clone())
    }
}

static SQL_IDENT_RE: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$"));

fn is_safe_ident(value: &str) -> bool {
    match SQL_IDENT_RE.as_ref() {
        Ok(re) => re.is_match(value),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_key("master", b"salt", "info").unwrap();
        let k2 = derive_key("master", b"salt", "info").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_inputs() {
        let k1 = derive_key("master", b"salt1", "info").unwrap();
        let k2 = derive_key("master", b"salt2", "info").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_length() {
        let k = derive_key("key", b"salt", "info").unwrap();
        assert_eq!(k.len(), KEY_LENGTH);
    }

    #[test]
    fn test_data_key_encrypt_decrypt_roundtrip() {
        let svc = test_service();
        let raw = [42u8; KEY_LENGTH];
        let encrypted = svc.encrypt_data_key(&raw).unwrap();
        let decrypted = svc.decrypt_data_key(&encrypted).unwrap();
        assert_eq!(decrypted, raw);
    }

    #[test]
    fn test_data_key_encrypted_format() {
        let svc = test_service();
        let raw = [1u8; KEY_LENGTH];
        let encrypted = svc.encrypt_data_key(&raw).unwrap();
        let parts: Vec<&str> = encrypted.split(':').collect();
        assert_eq!(parts.len(), 3); // iv:tag:ciphertext
    }

    #[test]
    fn test_data_key_different_ciphertexts() {
        let svc = test_service();
        let raw = [99u8; KEY_LENGTH];
        let e1 = svc.encrypt_data_key(&raw).unwrap();
        let e2 = svc.encrypt_data_key(&raw).unwrap();
        // Different IVs produce different ciphertexts
        assert_ne!(e1, e2);
        // But both decrypt to the same key
        assert_eq!(
            svc.decrypt_data_key(&e1).unwrap(),
            svc.decrypt_data_key(&e2).unwrap()
        );
    }

    #[test]
    fn test_data_key_tampered_ciphertext_fails() {
        let svc = test_service();
        let raw = [7u8; KEY_LENGTH];
        let encrypted = svc.encrypt_data_key(&raw).unwrap();
        let parts: Vec<&str> = encrypted.split(':').collect();
        // Tamper with ciphertext part
        let mut ct_bytes = B64.decode(parts[2]).unwrap();
        if let Some(b) = ct_bytes.last_mut() {
            *b ^= 0xFF;
        }
        let tampered = format!("{}:{}:{}", parts[0], parts[1], B64.encode(&ct_bytes));
        assert!(svc.decrypt_data_key(&tampered).is_err());
    }

    #[test]
    fn test_data_key_wrong_master_key_fails() {
        let svc1 = test_service();
        let raw = [5u8; KEY_LENGTH];
        let encrypted = svc1.encrypt_data_key(&raw).unwrap();

        let svc2 = test_service_with_key("different-key-that-is-32-chars!!");
        assert!(svc2.decrypt_data_key(&encrypted).is_err());
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = EncryptionService::hash("test@example.com", None);
        let h2 = EncryptionService::hash("test@example.com", None);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_hash_with_salt() {
        let h1 = EncryptionService::hash("test", Some("salt1"));
        let h2 = EncryptionService::hash("test", Some("salt2"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_generate_token_length() {
        let t = EncryptionService::generate_token(32);
        assert_eq!(t.len(), 32);
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let t1 = EncryptionService::generate_token(64);
        let t2 = EncryptionService::generate_token(64);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_hash_code_deterministic() {
        let h1 = hash_code("org-123");
        let h2 = hash_code("org-123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_code_different() {
        let h1 = hash_code("org-123");
        let h2 = hash_code("org-456");
        assert_ne!(h1, h2);
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

    fn test_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }

    fn test_service() -> EncryptionService {
        EncryptionService::new(
            test_pool(),
            SecurityConfig {
                encryption_key: "test-master-key-change-in-prod!!".into(),
                data_key_rotation_days: 90,
                audit_retention_days: 365,
                session_timeout_minutes: 30,
            },
        )
    }

    fn test_service_with_key(key: &str) -> EncryptionService {
        EncryptionService::new(
            test_pool(),
            SecurityConfig {
                encryption_key: key.into(),
                data_key_rotation_days: 90,
                audit_retention_days: 365,
                session_timeout_minutes: 30,
            },
        )
    }
}
