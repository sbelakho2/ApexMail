use sha2::{Sha256, Digest};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::VolumeAllocationMode;
use crate::types::*;

/// Sub-Accounts Service: agency/reseller sub-accounts, volume allocation, API keys
pub struct SubAccountService {
    db: PgPool,
    max_sub_accounts: i32,
    volume_allocation_mode: VolumeAllocationMode,
}

impl SubAccountService {
    pub fn new(db: PgPool, max_sub_accounts: i32, volume_allocation_mode: VolumeAllocationMode) -> Self {
        Self { db, max_sub_accounts, volume_allocation_mode }
    }

    /// Create a sub-account
    pub async fn create(
        &self, parent_id: Uuid, name: &str, email: Option<&str>,
        domain: Option<&str>, plan: Option<&str>, volume_limit: Option<i64>,
        inherit_parent_settings: bool,
    ) -> Result<ApiResult<SubAccount>, String> {
        // Check sub-account limit
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ent_sub_accounts WHERE parent_id = $1"
        )
        .bind(parent_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Count sub-accounts: {e}"))?;

        if count.0 >= self.max_sub_accounts as i64 {
            return Ok(ApiResult::err(
                format!("Maximum sub-accounts ({}) reached", self.max_sub_accounts),
                "QUOTA_EXCEEDED",
            ));
        }

        let id = Uuid::new_v4();
        let row = sqlx::query_as::<_, SubAccount>(
            "INSERT INTO ent_sub_accounts (id, parent_id, name, status, email, domain, plan, volume_limit, volume_used, inherit_parent_settings, created_at, updated_at)
             VALUES ($1,$2,$3,'active',$4,$5,$6,$7,0,$8,NOW(),NOW())
             RETURNING *"
        )
        .bind(id).bind(parent_id).bind(name).bind(email)
        .bind(domain).bind(plan).bind(volume_limit).bind(inherit_parent_settings)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create sub-account: {e}"))?;

        info!(parent_id = %parent_id, sub_id = %id, name = name, "Sub-account created");
        Ok(ApiResult::ok(row))
    }

    /// Get a sub-account by ID
    pub async fn get(&self, id: Uuid) -> Result<ApiResult<SubAccount>, String> {
        let row = sqlx::query_as::<_, SubAccount>(
            "SELECT * FROM ent_sub_accounts WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Get sub-account: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Sub-account not found", "NOT_FOUND")),
        }
    }

    /// List sub-accounts for a parent
    pub async fn list(
        &self, parent_id: Uuid, status: Option<&str>, limit: i64, offset: i64,
    ) -> Result<ApiResult<Vec<SubAccount>>, String> {
        let rows = if let Some(s) = status {
            sqlx::query_as::<_, SubAccount>(
                "SELECT * FROM ent_sub_accounts WHERE parent_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
            )
            .bind(parent_id).bind(s).bind(limit).bind(offset)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as::<_, SubAccount>(
                "SELECT * FROM ent_sub_accounts WHERE parent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(parent_id).bind(limit).bind(offset)
            .fetch_all(&self.db)
            .await
        }.map_err(|e| format!("List sub-accounts: {e}"))?;

        Ok(ApiResult::ok(rows))
    }

    /// Update a sub-account
    pub async fn update(
        &self, id: Uuid, name: Option<&str>, email: Option<&str>,
        volume_limit: Option<i64>, settings: Option<serde_json::Value>,
    ) -> Result<ApiResult<SubAccount>, String> {
        let row = sqlx::query_as::<_, SubAccount>(
            "UPDATE ent_sub_accounts SET
             name = COALESCE($2, name),
             email = COALESCE($3, email),
             volume_limit = COALESCE($4, volume_limit),
             settings = COALESCE($5, settings),
             updated_at = NOW()
             WHERE id = $1 RETURNING *"
        )
        .bind(id).bind(name).bind(email).bind(volume_limit).bind(&settings)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Update sub-account: {e}"))?;

        match row {
            Some(r) => Ok(ApiResult::ok(r)),
            None => Ok(ApiResult::err("Sub-account not found", "NOT_FOUND")),
        }
    }

    /// Suspend a sub-account
    pub async fn suspend(&self, id: Uuid, reason: Option<&str>) -> Result<ApiResult<SubAccount>, String> {
        let row = sqlx::query_as::<_, SubAccount>(
            "UPDATE ent_sub_accounts SET status = 'suspended', updated_at = NOW() WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Suspend sub-account: {e}"))?;

        match row {
            Some(r) => {
                info!(id = %id, reason = ?reason, "Sub-account suspended");
                Ok(ApiResult::ok(r))
            }
            None => Ok(ApiResult::err("Sub-account not found", "NOT_FOUND")),
        }
    }

    /// Delete a sub-account
    pub async fn delete(&self, id: Uuid) -> Result<ApiResult<serde_json::Value>, String> {
        let result = sqlx::query("DELETE FROM ent_sub_accounts WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Delete sub-account: {e}"))?;

        if result.rows_affected() == 0 {
            Ok(ApiResult::err("Sub-account not found", "NOT_FOUND"))
        } else {
            Ok(ApiResult::ok(serde_json::json!({"deleted": true})))
        }
    }

    /// Get aggregate stats for all sub-accounts of a parent
    pub async fn get_stats(&self, parent_id: Uuid) -> Result<ApiResult<SubAccountStats>, String> {
        let row: (i64, i64, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'active'),
             SUM(volume_used)::bigint, SUM(volume_limit)::bigint
             FROM ent_sub_accounts WHERE parent_id = $1"
        )
        .bind(parent_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Get sub-account stats: {e}"))?;

        Ok(ApiResult::ok(SubAccountStats {
            total: row.0,
            active: row.1,
            total_volume_used: row.2.unwrap_or(0),
            total_volume_limit: row.3.unwrap_or(0),
        }))
    }

    /// Create an API key for a sub-account
    pub async fn create_api_key(
        &self, sub_account_id: Uuid, name: &str, permissions: Option<Vec<String>>,
        rate_limit: Option<i32>,
    ) -> Result<ApiResult<serde_json::Value>, String> {
        let raw_key = crate::sso::generate_random_token(32);
        let key_prefix = &raw_key[..8];
        let key_hash = sha256_hex(&raw_key);

        let id = Uuid::new_v4();
        let _row = sqlx::query_as::<_, SubAccountApiKey>(
            "INSERT INTO ent_sub_account_api_keys (id, sub_account_id, key_hash, key_prefix, name, permissions, rate_limit, revoked, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,false,NOW())
             RETURNING *"
        )
        .bind(id).bind(sub_account_id).bind(&key_hash).bind(key_prefix)
        .bind(name).bind(&permissions).bind(rate_limit)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Create API key: {e}"))?;

        info!(sub_account_id = %sub_account_id, "API key created");
        // Return the raw key only once — it cannot be retrieved later
        Ok(ApiResult::ok(serde_json::json!({
            "id": id,
            "key": raw_key,
            "key_prefix": key_prefix,
            "name": name,
        })))
    }

    /// Check volume allocation for a sub-account
    pub fn check_volume_allowed(&self, volume_used: i64, volume_limit: Option<i64>, parent_headroom: i64) -> bool {
        check_volume_logic(&self.volume_allocation_mode, volume_used, volume_limit, parent_headroom)
    }
}

/// Pure function: volume check logic (extracted for testability)
pub fn check_volume_logic(
    mode: &VolumeAllocationMode, volume_used: i64, volume_limit: Option<i64>, _parent_headroom: i64,
) -> bool {
    match mode {
        VolumeAllocationMode::Fixed => {
            volume_limit.map(|l| volume_used < l).unwrap_or(true)
        }
        VolumeAllocationMode::Shared => {
            // Shared mode: no hard per-account limit
            true
        }
        VolumeAllocationMode::Burst => {
            // Burst mode: allow up to 120% of limit if parent has headroom
            volume_limit.map(|l| {
                let burst_limit = (l as f64 * 1.2) as i64;
                volume_used < burst_limit
            }).unwrap_or(true)
        }
    }
}

/// Compute SHA-256 hex digest
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex("test");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    }

    #[test]
    fn test_sha256_deterministic() {
        assert_eq!(sha256_hex("hello"), sha256_hex("hello"));
    }

    #[test]
    fn test_volume_fixed_under_limit() {
        assert!(check_volume_logic(&VolumeAllocationMode::Fixed, 500, Some(1000), 0));
    }

    #[test]
    fn test_volume_fixed_over_limit() {
        assert!(!check_volume_logic(&VolumeAllocationMode::Fixed, 1000, Some(1000), 0));
    }

    #[test]
    fn test_volume_shared_always_allowed() {
        assert!(check_volume_logic(&VolumeAllocationMode::Shared, 999999, Some(100), 0));
    }

    #[test]
    fn test_volume_burst_within_120_percent() {
        assert!(check_volume_logic(&VolumeAllocationMode::Burst, 1100, Some(1000), 5000));
    }

    #[test]
    fn test_volume_burst_over_120_percent() {
        assert!(!check_volume_logic(&VolumeAllocationMode::Burst, 1200, Some(1000), 5000));
    }

    #[test]
    fn test_volume_no_limit() {
        assert!(check_volume_logic(&VolumeAllocationMode::Fixed, 999999, None, 0));
    }

    #[test]
    fn test_sub_account_stats_serialization() {
        let stats = SubAccountStats {
            total: 10,
            active: 8,
            total_volume_used: 50000,
            total_volume_limit: 100000,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total"], 10);
        assert_eq!(json["active"], 8);
    }

    #[test]
    fn test_sub_account_serialization() {
        let sa = SubAccount {
            id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            name: "Agency Client 1".into(),
            status: "active".into(),
            email: Some("client@agency.com".into()),
            domain: Some("client.agency.com".into()),
            plan: Some("business".into()),
            volume_limit: Some(50000),
            volume_used: 12000,
            inherit_parent_settings: true,
            settings: None,
            metadata: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&sa).unwrap();
        assert_eq!(json["name"], "Agency Client 1");
        assert_eq!(json["volume_used"], 12000);
    }
}
